//go:build integration

package antispam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPostfixScopeAgainstRspamd loads CSM's Postfix files into a real rspamd
// and scans with rspamc the way the milter asks. Needs rspamd 4.2 and rspamc
// on PATH; the rspamd image has no Go, so mount a Linux Go toolchain:
//
//	container run --rm -u root --entrypoint /usr/local/go/bin/go \
//	  -v $PWD:/src -v <linux go root>:/usr/local/go:ro -v <module cache>:/gomod -w /src \
//	  -e GOMODCACHE=/gomod -e GOFLAGS=-mod=mod -e GOPROXY=off -e CGO_ENABLED=0 -e GOCACHE=/tmp/gocache \
//	  docker.io/rspamd/rspamd:4.2.3 test -tags integration -count=1 -run TestPostfixScopeAgainstRspamd ./internal/antispam/
func TestPostfixScopeAgainstRspamd(t *testing.T) {
	for _, tool := range []string{"rspamd", "rspamc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH", tool)
		}
	}
	scope := Settings{
		Socket: DefaultSocket, Stack: StackPostfix, Feeds: []string{FeedRspamdMaps},
		Exempt:    []string{"exempt@example.com", "example.org"},
		ScopeNets: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:1::/48")},
	}
	remote := []string{"--ip", "203.0.113.5"}
	rcpt := func(addrs ...string) []string {
		var out []string
		for _, a := range addrs {
			out = append(out, "--rcpt", a)
		}
		return out
	}
	join := func(parts ...[]string) []string {
		var out []string
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}

	t.Run("enforce", func(t *testing.T) {
		s := scope
		s.RejectScore, s.TagScore = 15, 6
		r := startScopeRspamd(t, s)
		for _, c := range []scopeCase{
			{name: "remote", score: 20, forged: "No, forged", args: join(remote, rcpt("user@example.com")),
				action: "reject", record: "on reject", strip: true, status: "Yes, score="},
			{name: "authenticated", score: 20, forged: "No, forged", args: join(remote, []string{"--user", "sender@example.net"}, rcpt("user@example.com")),
				action: "no action", strip: true},
			{name: "local", score: 20, forged: "No, forged", args: join([]string{"--ip", "127.0.0.1"}, rcpt("user@example.com")),
				action: "no action", strip: true},
			{name: "infra ipv4", score: 20, args: join([]string{"--ip", "198.51.100.7"}, rcpt("user@example.com")), action: "no action"},
			{name: "infra ipv6", score: 20, args: join([]string{"--ip", "2001:db8:1::5"}, rcpt("user@example.com")), action: "no action"},
			{name: "exempt mailbox", score: 20, args: join(remote, rcpt("exempt@example.com")),
				action: "no action", record: "off unfiltered"},
			{name: "exempt domain", score: 20, args: join(remote, rcpt("a@example.org", "B@Example.ORG")),
				action: "no action", record: "off unfiltered"},
			{name: "exempt and normal", score: 20, args: join(remote, rcpt("exempt@example.com", "user@example.com")),
				action: "reject", record: "on reject"},
			{name: "forged yes", score: -40, forged: "Yes, forged", args: join(remote, rcpt("user@example.com")),
				action: "no action", record: "on none", strip: true, status: "No, score="},
		} {
			r.check(t, s, c)
		}
	})

	// In dry run the host's own actions, rspamd's defaults here, keep
	// deciding; the record carries the decision CSM's thresholds would take.
	t.Run("dry run", func(t *testing.T) {
		s := scope
		s.DryRun, s.RejectScore, s.TagScore = true, 100, 10
		r := startScopeRspamd(t, s)
		for _, c := range []scopeCase{
			{name: "remote", score: 50, args: join(remote, rcpt("user@example.com")), action: "reject", record: "on tag"},
			{name: "exempt mailbox", score: 50, args: join(remote, rcpt("exempt@example.com")), action: "reject", record: "off unfiltered"},
			{name: "authenticated", score: -40, forged: "Yes, forged", args: join(remote, []string{"--user", "sender@example.net"}, rcpt("user@example.com")),
				action: "no action", strip: true},
		} {
			r.check(t, s, c)
		}
	})
}

// scopeCase is one rspamc scan and what rspamd must answer.
type scopeCase struct {
	name   string
	score  int    // weight of the test symbol
	forged string // inbound X-Spam-Status, if any
	args   []string
	action string
	// record is the policy and decision of the one scan record, or empty
	// when the message must log none.
	record string
	// strip asks for X-Spam-Status in the milter's remove list; status is
	// the start of the X-Spam-Status it adds, or none when strip is set
	// and status is empty.
	strip  bool
	status string
}

type scopeReply struct {
	Action string  `json:"action"`
	Score  float64 `json:"score"`
	Milter struct {
		Add map[string]struct {
			Value string `json:"value"`
		} `json:"add_headers"`
		Remove map[string]int `json:"remove_headers"`
	} `json:"milter"`
}

type scopeRspamd struct {
	addr, log string
	scans     int
}

// scopeTestSymbol adds the X-Test-Score header's value to the score, which
// a GTUBE message cannot do: GTUBE ends the scan before any prefilter.
const scopeTestSymbol = `rspamd_config:register_symbol({
  name = 'CSM_TEST_SCORE',
  score = 1.0,
  callback = function(task)
    local h = task:get_header('X-Test-Score')
    if h then
      task:insert_result('CSM_TEST_SCORE', tonumber(h))
    end
  end,
})
`

// startScopeRspamd runs rspamd with CSM's files for s in a temporary tree
// that stands in for /etc/rspamd, a normal worker on a loopback port and DNS
// that fails at once.
func startScopeRspamd(t *testing.T, s Settings) *scopeRspamd {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, text string) {
		t.Helper()
		p := filepath.Join(dir, rel)
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
		rel, ok := strings.CutPrefix(p, "/etc/rspamd/")
		if !ok {
			t.Fatalf("%s is not an rspamd file", p)
		}
		write(rel, text)
	}
	write("lua.local.d/csm_test_score.lua", scopeTestSymbol)
	write("local.d/options.inc", "dns {\n  nameserver = [\"127.0.0.1:1\"];\n  timeout = 0.5s;\n  retransmits = 0;\n}\n")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "rspamd.log")
	write("rspamd.conf", fmt.Sprintf(`.include "$CONFDIR/common.conf"
options {
  pidfile = %q;
  .include "$CONFDIR/options.inc"
  .include(try=true; priority=1,duplicate=merge) "$LOCAL_CONFDIR/local.d/options.inc"
}
logging {
  type = "file";
  filename = %q;
  .include "$CONFDIR/logging.inc"
}
worker "normal" {
  bind_socket = %q;
  .include "$CONFDIR/worker-normal.inc"
}
`, filepath.Join(dir, "rspamd.pid"), log, addr))
	args := []string{"-f", "-c", filepath.Join(dir, "rspamd.conf")}
	for _, v := range []string{"LOCAL_CONFDIR", "DBDIR", "RUNDIR", "LOGDIR"} {
		args = append(args, "--var", v+"="+dir)
	}
	if os.Geteuid() == 0 {
		// A container runs the test as root; -i lets rspamd's workers run as
		// root too.
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
	for deadline := time.Now().Add(60 * time.Second); ; {
		select {
		case <-done:
			text, _ := os.ReadFile(log)
			t.Fatalf("rspamd exited: %v\n%s\n%s", waitErr, out.String(), text)
		default:
		}
		if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rspamd is not listening on %s", addr)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return &scopeRspamd{addr: addr, log: log}
}

// scopeRecord is a scan record as Task 5 reads it: logged from CSM's Lua
// file, then the full grammar.
var scopeRecord = regexp.MustCompile(`; lua; csm_scope\.lua:[0-9]+: CSM-ANTISPAM (event=scan mode=(?:enforce|dry-run) policy=(?:on|off) result=ok score=(-?[0-9]+) action="[a-z_ ]*" decision=(?:unfiltered|reject|tag|none) ip=[0-9a-f.:]* qid=[0-9A-Za-z_]*)$`)

func (r *scopeRspamd) check(t *testing.T, s Settings, c scopeCase) {
	t.Helper()
	r.scans++
	qid := fmt.Sprintf("CSMSCOPE%02d", r.scans)
	msg := fmt.Sprintf("From: sender@example.net\r\nTo: user@example.com\r\nSubject: scope test\r\nX-Test-Score: %d\r\n", c.score)
	if c.forged != "" {
		msg += "X-Spam-Status: " + c.forged + "\r\n"
	}
	file := filepath.Join(t.TempDir(), qid+".eml")
	if err := os.WriteFile(file, []byte(msg+"\r\nHello.\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-h", r.addr, "-t", "30", "--compact", "-j", "--queue-id", qid}, c.args...)
	out, err := exec.Command("rspamc", append(args, file)...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: rspamc: %v\n%s", c.name, err, out)
	}
	var reply scopeReply
	if err := json.Unmarshal(out, &reply); err != nil {
		t.Fatalf("%s: rspamc reply: %v\n%s", c.name, err, out)
	}
	if reply.Action != c.action {
		t.Errorf("%s: action %q (score %.2f), want %q", c.name, reply.Action, reply.Score, c.action)
	}
	if _, removed := reply.Milter.Remove["X-Spam-Status"]; c.strip && !removed {
		t.Errorf("%s: milter keeps an inbound X-Spam-Status: %s", c.name, out)
	}
	status, added := reply.Milter.Add["X-Spam-Status"]
	switch {
	case c.status != "" && !strings.HasPrefix(status.Value, c.status):
		t.Errorf("%s: milter adds X-Spam-Status %q, want %q...", c.name, status.Value, c.status)
	case c.status == "" && c.strip && added:
		t.Errorf("%s: milter adds X-Spam-Status %q to mail CSM does not score", c.name, status.Value)
	}

	records := r.records(t, qid)
	if c.record == "" {
		if len(records) != 0 {
			t.Errorf("%s: logged %q for mail CSM does not score", c.name, records)
		}
		return
	}
	if len(records) != 1 {
		t.Fatalf("%s: logged %d scan records, want 1: %q", c.name, len(records), records)
	}
	m := scopeRecord.FindStringSubmatch(records[0])
	if m == nil {
		t.Fatalf("%s: scan record outside the grammar: %q", c.name, records[0])
	}
	// rspamc prints the score rounded to hundredths; the record holds it in
	// tenths, rounded down.
	score, _ := strconv.Atoi(m[2])
	if want := int(math.Floor(reply.Score * 10)); score < want-1 || score > want+1 {
		t.Errorf("%s: record score %d, want about %d", c.name, score, want)
	}
	mode := "enforce"
	if s.DryRun {
		mode = "dry-run"
	}
	ip := ""
	for i, a := range c.args[:len(c.args)-1] {
		if a == "--ip" {
			ip = c.args[i+1]
		}
	}
	policy, decision, _ := strings.Cut(c.record, " ")
	want := fmt.Sprintf(`event=scan mode=%s policy=%s result=ok score=%d action="%s" decision=%s ip=%s qid=%s`,
		mode, policy, score, reply.Action, decision, ip, qid)
	if m[1] != want {
		t.Errorf("%s: scan record\n%s\nwant\n%s", c.name, m[1], want)
	}
}

// records waits for rspamd's own log line for qid, which follows the scan
// record, and returns the scan records naming qid.
func (r *scopeRspamd) records(t *testing.T, qid string) []string {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); ; {
		text, err := os.ReadFile(r.log)
		if err != nil {
			t.Fatal(err)
		}
		var found []string
		logged := false
		for _, line := range strings.Split(string(text), "\n") {
			if strings.Contains(line, "qid: <"+qid+">,") {
				logged = true
			}
			if strings.Contains(line, "CSM-ANTISPAM") && strings.Contains(line, qid) {
				found = append(found, line)
			}
		}
		if logged {
			return found
		}
		if time.Now().After(deadline) {
			t.Fatalf("rspamd logged no result for %s", qid)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
