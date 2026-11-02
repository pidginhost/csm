//go:build integration

package antispam

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// TestFuzzyWorkerUsesDedicatedRedisWithoutGlobalAuth loads CSM's learning
// files with a dedicated Redis into rspamd 4.2, whose global redis section
// names another Redis with a password, then learns a message and scans it.
// The hash must land in the dedicated, passwordless Redis, which must never
// receive AUTH: rspamd's fuzzy worker merges the global password into its
// own servers unless CSM's file overrides it. Needs rspamd, rspamadm,
// rspamc and a glibc redis-server on PATH; the rspamd image has neither Go
// nor Redis, so mount both:
//
//	container run --rm -m 8g -u root --entrypoint /usr/local/go/bin/go \
//	  -v $PWD:/src -v <linux go root>:/usr/local/go:ro -v <redis 7 bookworm bin>:/opt/redis:ro \
//	  -v <module cache>:/gomod -w /src -e PATH=/opt/redis:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
//	  -e GOMODCACHE=/gomod -e GOFLAGS=-mod=mod -e GOPROXY=off -e CGO_ENABLED=0 -e GOCACHE=/tmp/gocache \
//	  docker.io/rspamd/rspamd:4.2.3 test -tags integration -count=1 -run TestFuzzyWorkerUsesDedicatedRedisWithoutGlobalAuth ./internal/antispam/
func TestFuzzyWorkerUsesDedicatedRedisWithoutGlobalAuth(t *testing.T) {
	for _, tool := range []string{"rspamd", "rspamadm", "rspamc", "redis-server"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH", tool)
		}
	}
	dir := t.TempDir()
	learning := startRedis(t, dir, "learning")
	global := startRedis(t, dir, "global", "--requirepass", "x")
	keys := LearningKeys{
		Fuzzy: NewSecret(randomHex(t, 32)), Shingles: NewSecret(randomHex(t, 32)),
		Read: rspamdKeypair(t), Write: rspamdKeypair(t), Prefix: "csmfz_" + randomHex(t, 16),
	}
	s := Settings{Socket: DefaultSocket, RejectScore: DefaultRejectScore, TagScore: DefaultTagScore,
		Learning: true, LearningDir: DefaultLearningDir, LearningRedisSocket: learning, LearningKeys: keys}
	r := startLearningRspamd(t, dir, s, global)

	msg := filepath.Join(dir, "spam.eml")
	var body strings.Builder
	for i := 0; body.Len() < 4096; i++ {
		fmt.Fprintf(&body, "Offer %d: claim the limited bonus for example.org members before the deadline passes. ", i)
	}
	text := "From: sender@example.net\r\nTo: user@example.com\r\nSubject: dedicated redis\r\n" +
		"Message-ID: <dedicated@example.net>\r\n\r\n" + body.String() + "\r\n"
	if err := os.WriteFile(msg, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("rspamc", "-h", r.controller, "-t", "30", "fuzzy_add", "-f", "1", "-w", "10", msg).CombinedOutput(); err != nil {
		t.Fatalf("rspamc fuzzy_add: %v\n%s", err, out)
	}

	ctx := context.Background()
	dedicated := redis.NewClient(&redis.Options{Network: "unix", Addr: learning, Protocol: 2, DisableIdentity: true})
	defer func() { _ = dedicated.Close() }()
	var stored []string
	for deadline := time.Now().Add(45 * time.Second); len(stored) == 0; time.Sleep(500 * time.Millisecond) {
		var err error
		if stored, _, err = dedicated.Scan(ctx, 0, keys.Prefix+"*", 1000).Result(); err != nil {
			t.Fatal(err)
		}
		if len(stored) == 0 && time.Now().After(deadline) {
			log, _ := os.ReadFile(r.log)
			t.Fatalf("no hash reached the dedicated Redis\n%s", log)
		}
	}
	out, err := exec.Command("rspamc", "-h", r.normal, "-t", "30", "-j", "symbols", msg).CombinedOutput()
	if err != nil {
		t.Fatalf("rspamc symbols: %v\n%s", err, out)
	}
	var reply scopeReply
	if err = json.Unmarshal(out, &reply); err != nil {
		t.Fatalf("rspamc reply: %v\n%s", err, out)
	}
	if _, ok := reply.Symbols["CSM_FUZZY_SPAM"]; !ok {
		t.Fatalf("the learned message does not match: %s", out)
	}
	stats, err := dedicated.Info(ctx, "commandstats").Result()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stats, "cmdstat_auth:") {
		t.Fatalf("the dedicated Redis received AUTH:\n%s", stats)
	}
	other := redis.NewClient(&redis.Options{Network: "unix", Addr: global, Password: "x", Protocol: 2, DisableIdentity: true})
	defer func() { _ = other.Close() }()
	if leaked, _, scanErr := other.Scan(ctx, 0, keys.Prefix+"*", 1000).Result(); scanErr != nil || len(leaked) != 0 {
		t.Fatalf("rspamd's global Redis holds learning keys: %v %v", leaked, scanErr)
	}

	// CSM's verification accepts what rspamd loaded.
	dump := func(args ...string) []byte {
		t.Helper()
		argv := append(append([]string{}, r.vars...), "configdump", "-c", r.conf, "-j")
		text, dumpErr := exec.Command("rspamadm", append(argv, args...)...).Output()
		if dumpErr != nil {
			t.Fatalf("rspamadm configdump %v: %v", args, dumpErr)
		}
		return text
	}
	full := dump()
	root, err := ParseRspamdDumpObject(full)
	if err != nil {
		t.Fatal(err)
	}
	// The shared-Redis check reads every section of this dump strictly.
	strictDump(t, full)
	actions, err := ParseActions(dump("actions"))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckLearningLoaded(dump("fuzzy_check"), root["worker"], dump("group"), r.get(t, "/symbols"), actions, keys, learning); err != nil {
		t.Fatalf("CSM rejects the loaded learning configuration: %v", err)
	}
}

// strictDump fails when an object anywhere in raw repeats a key.
func strictDump(t *testing.T, raw json.RawMessage) {
	t.Helper()
	switch trimmed := bytes.TrimSpace(raw); {
	case len(trimmed) > 0 && trimmed[0] == '{':
		obj, err := ParseRspamdDumpObject(trimmed)
		if err != nil {
			t.Fatalf("configdump: %v", err)
		}
		for _, v := range obj {
			strictDump(t, v)
		}
	case len(trimmed) > 0 && trimmed[0] == '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			t.Fatalf("configdump: %v", err)
		}
		for _, v := range items {
			strictDump(t, v)
		}
	}
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func rspamdKeypair(t *testing.T) Keypair {
	t.Helper()
	out, err := exec.Command("rspamadm", "keypair", "-j").Output()
	if err != nil {
		t.Fatal(err)
	}
	var kp struct {
		Keypair *struct {
			Pubkey  string `json:"pubkey"`
			Privkey string `json:"privkey"`
		} `json:"keypair"`
		Pubkey  string `json:"pubkey"`
		Privkey string `json:"privkey"`
	}
	if err := json.Unmarshal(out, &kp); err != nil {
		t.Fatal(err)
	}
	if kp.Keypair != nil {
		kp.Pubkey, kp.Privkey = kp.Keypair.Pubkey, kp.Keypair.Privkey
	}
	k := Keypair{Public: kp.Pubkey, Private: NewSecret(kp.Privkey)}
	if err := k.Validate(); err != nil {
		t.Fatal(err)
	}
	return k
}

// startRedis runs a socket-only redis-server in dir and returns its socket.
func startRedis(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	sock := filepath.Join(dir, name+".sock")
	cmd := exec.Command("redis-server", append([]string{
		"--port", "0", "--unixsocket", sock, "--unixsocketperm", "700", "--save", "", "--appendonly", "no",
		"--maxmemory", "64mb", "--maxmemory-policy", "noeviction", "--dir", dir, "--logfile", filepath.Join(dir, name+".log"),
	}, args...)...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if conn, err := net.Dial("unix", sock); err == nil {
			_ = conn.Close()
			return sock
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(filepath.Join(dir, name+".log"))
			t.Fatalf("redis-server %s is not listening\n%s", name, log)
		}
	}
}

type learningRspamd struct {
	normal, controller, conf, log string
	// vars are rspamadm's options selecting the test configuration.
	vars []string
}

// get reads one controller path.
func (r *learningRspamd) get(t *testing.T, path string) []byte {
	t.Helper()
	resp, err := http.Get("http://" + r.controller + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d %v", path, resp.StatusCode, err)
	}
	return body
}

// startLearningRspamd runs rspamd with CSM's rspamd files for s, a normal,
// controller and fuzzy worker laid out like the packaged rspamd.conf, and a
// global redis section naming globalRedis with the password "x".
func startLearningRspamd(t *testing.T, dir string, s Settings, globalRedis string) *learningRspamd {
	t.Helper()
	conf := filepath.Join(dir, "conf")
	write := func(rel, text string) {
		t.Helper()
		p := filepath.Join(conf, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := ManagedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	for p, text := range files {
		if rel, ok := strings.CutPrefix(p, "/etc/rspamd/"); ok {
			write(rel, text)
		}
	}
	write("local.d/redis.conf", fmt.Sprintf("servers = %q;\npassword = \"x\";\n", globalRedis))
	// Pending fuzzy writes reach Redis on this timer, 60 seconds by default.
	write("local.d/worker-fuzzy.inc", "sync = 1s;\n")
	write("local.d/options.inc", "dns {\n  nameserver = [\"127.0.0.1:1\"];\n  timeout = 0.5s;\n  retransmits = 0;\n}\n")
	addr := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		return l.Addr().String()
	}
	r := &learningRspamd{normal: addr(), controller: addr(), conf: filepath.Join(conf, "rspamd.conf"), log: filepath.Join(dir, "rspamd.log")}
	include := func(name string) string {
		return fmt.Sprintf(".include \"$CONFDIR/%[1]s\"\n  .include(try=true; priority=1,duplicate=merge) \"$LOCAL_CONFDIR/local.d/%[1]s\"\n"+
			"  .include(try=true; priority=10) \"$LOCAL_CONFDIR/override.d/%[1]s\"", name)
	}
	write("rspamd.conf", fmt.Sprintf(`.include "$CONFDIR/common.conf"
options {
  pidfile = %q;
  %s
}
logging {
  type = "file";
  filename = %q;
  .include "$CONFDIR/logging.inc"
}
worker "normal" {
  bind_socket = %q;
  %s
}
worker "controller" {
  bind_socket = %q;
  %s
}
worker "fuzzy" {
  bind_socket = "localhost:11335";
  count = -1;
  %s
}
`, filepath.Join(dir, "rspamd.pid"), include("options.inc"), r.log, r.normal, include("worker-normal.inc"),
		r.controller, include("worker-controller.inc"), include("worker-fuzzy.inc")))
	args := []string{"-f", "-c", r.conf}
	for _, v := range []string{"LOCAL_CONFDIR=" + conf, "DBDIR=" + dir, "RUNDIR=" + dir, "LOGDIR=" + dir} {
		args = append(args, "--var", v)
		r.vars = append(r.vars, "--var="+v)
	}
	if os.Geteuid() == 0 {
		args = append(args, "-i")
	}
	cmd := exec.Command("rspamd", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		select {
		case <-done:
			text, _ := os.ReadFile(r.log)
			t.Fatalf("rspamd exited: %v\n%s\n%s", waitErr, out.String(), text)
		default:
		}
		up := true
		for _, a := range []string{r.normal, r.controller} {
			conn, err := net.DialTimeout("tcp", a, time.Second)
			if err != nil {
				up = false
				break
			}
			_ = conn.Close()
		}
		if up {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("rspamd is not listening")
		}
	}
}
