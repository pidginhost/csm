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
	"slices"
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
	forgedAuth := []string{
		"forged.example.net; dkim=pass header.d=forged.example.net",
		"forged.example.org; spf=pass smtp.mailfrom=forged@example.org",
	}
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
				action: "reject", record: "on reject", strip: true, status: "Yes, score=", has: "MISSING_DATE", authHeaders: forgedAuth},
			{name: "authenticated", score: 20, forged: "No, forged", args: join(remote, []string{"--user", "sender@example.net"}, rcpt("user@example.com")),
				action: "no action", strip: true, authHeaders: forgedAuth, keepAuth: true},
			{name: "local", score: 20, forged: "No, forged", args: join([]string{"--ip", "127.0.0.1"}, rcpt("user@example.com")),
				action: "no action", strip: true, authHeaders: forgedAuth, keepAuth: true},
			{name: "local ipv6", score: 20, forged: "No, forged", args: join([]string{"--ip", "::1"}, rcpt("user@example.com")),
				action: "no action", strip: true, authHeaders: forgedAuth, keepAuth: true},
			{name: "infra ipv4", score: 20, args: join([]string{"--ip", "198.51.100.7"}, rcpt("user@example.com")), action: "no action", authHeaders: forgedAuth},
			{name: "infra ipv6", score: 20, args: join([]string{"--ip", "2001:db8:1::5"}, rcpt("user@example.com")), action: "no action", authHeaders: forgedAuth},
			{name: "exempt mailbox", score: 20, args: join(remote, rcpt("exempt@example.com")),
				action: "no action", record: "off unfiltered", authHeaders: forgedAuth},
			{name: "exempt domain", score: 20, args: join(remote, rcpt("a@example.org", "B@Example.ORG")),
				action: "no action", record: "off unfiltered", authHeaders: forgedAuth},
			{name: "exempt and normal", score: 20, args: join(remote, rcpt("exempt@example.com", "user@example.com")),
				action: "reject", record: "on reject", authHeaders: forgedAuth},
			{name: "forged yes", score: -40, forged: "Yes, forged", args: join(remote, rcpt("user@example.com")),
				action: "no action", record: "on none", strip: true, status: "No, score=", authHeaders: forgedAuth},
			{name: "remote without auth headers", score: -40, args: join(remote, rcpt("user@example.com")),
				action: "no action", record: "on none", strip: true, status: "No, score="},
		} {
			r.check(t, s, c)
		}
		// The operator's settings rules keep working beside CSM's scope: on
		// scored mail they apply as written. On mail CSM never enforces on,
		// CSM's no-action limits replace the rule's own reject and add_header
		// limits while the rest of the rule stays in the task's settings.
		allowed, quiet := []string{"--from", "sender@allowed.example.net"}, []string{"--from", "sender@quiet.example.net"}
		for _, c := range []scopeCase{
			{name: "operator allow", score: 20, args: join(remote, allowed, rcpt("user@example.com")),
				action: "no action", record: "on reject", authHeaders: forgedAuth},
			{name: "operator rule", score: 20, args: join(remote, quiet, rcpt("user@example.com")),
				action: "reject", record: "on reject", lacks: "MISSING_DATE", limits: map[string]float64{"add header": 3}, kept: true, authHeaders: forgedAuth},
			{name: "operator rule, authenticated", score: 20, forged: "No, forged", args: join(remote, quiet, []string{"--user", "sender@example.net"}, rcpt("user@example.com")),
				action: "no action", strip: true, lacks: "MISSING_DATE", lifted: true, kept: true, authHeaders: forgedAuth, keepAuth: true},
			{name: "operator rule, local", score: 20, args: join([]string{"--ip", "127.0.0.1"}, quiet, rcpt("user@example.com")),
				action: "no action", lacks: "MISSING_DATE", lifted: true, kept: true, authHeaders: forgedAuth, keepAuth: true},
			{name: "operator netblock, infra", score: 20, args: join([]string{"--ip", "198.51.100.7"}, rcpt("user@example.com")),
				action: "no action", lacks: "MISSING_DATE", lifted: true, kept: true, authHeaders: forgedAuth},
			{name: "operator rule, exempt", score: 20, args: join(remote, quiet, rcpt("exempt@example.com")),
				action: "no action", record: "off unfiltered", lacks: "MISSING_DATE", lifted: true, kept: true, authHeaders: forgedAuth},
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
			{name: "remote", score: 50, args: join(remote, rcpt("user@example.com")), action: "reject", record: "on tag", authHeaders: forgedAuth},
			{name: "exempt mailbox", score: 50, args: join(remote, rcpt("exempt@example.com")), action: "reject", record: "off unfiltered", authHeaders: forgedAuth},
			{name: "remote without auth headers", score: -40, args: join(remote, rcpt("user@example.com")),
				action: "no action", record: "on none", strip: true, status: "No, score="},
			{name: "authenticated", score: -40, forged: "Yes, forged", args: join(remote, []string{"--user", "sender@example.net"}, rcpt("user@example.com")),
				action: "no action", strip: true, authHeaders: forgedAuth, keepAuth: true},
			{name: "local ipv6", score: -40, forged: "Yes, forged", args: join([]string{"--ip", "::1"}, rcpt("user@example.com")),
				action: "no action", strip: true, authHeaders: forgedAuth, keepAuth: true},
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
	// authHeaders are inbound Authentication-Results values. keepAuth asks
	// for no additions or removals; otherwise every copy must be replaced.
	authHeaders []string
	keepAuth    bool
	// has and lacks name a symbol the reply must or must not carry.
	has, lacks string
	// limits are action thresholds rspamd must report.
	limits map[string]float64
	// kept asks for the operator's symbols_disabled in the task's settings
	// at the end of the scan.
	kept bool
	// lifted asks for CSM's no-action limits: rspamd reports them, and no
	// underscore alias left in the task's settings competes with them.
	lifted bool
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
	Symbols    map[string]json.RawMessage `json:"symbols"`
	Thresholds map[string]float64         `json:"thresholds"`
}

type scopeRspamd struct {
	addr, log string
	scans     int
}

// scopeTestSymbol adds the X-Test-Score header's value to the score, which
// a GTUBE message cannot do: GTUBE ends the scan before any prefilter. It
// also logs the task's final settings.
const scopeTestSymbol = `local rspamd_logger = require 'rspamd_logger'
local ucl = require 'ucl'
rspamd_config:register_symbol({
  name = 'CSM_TEST_SETTINGS',
  type = 'idempotent',
  callback = function(task)
    local s = task:get_settings()
    rspamd_logger.infox(task, '%s', 'CSM-TEST settings=' .. (s and ucl.to_format(s, 'json-compact') or 'null') ..
      ' qid=' .. (task:get_queue_id() or ''))
  end,
})
rspamd_config:register_symbol({
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

// operatorSettings are operator rules in local.d/settings.conf, as a host
// keeps them: an allow rule for a sender domain, a rule for another sender
// domain that drops a symbol and sets an add_header limit, and one for the
// operator's own netblock that drops a symbol.
const operatorSettings = `operator_allow {
  priority = high;
  from = "@allowed.example.net";
  apply {
    actions {
      reject = 1000;
      "add header" = 1000;
      greylist = 1000;
    }
  }
}
operator_quiet {
  priority = high;
  from = "@quiet.example.net";
  apply {
    symbols_disabled = ["MISSING_DATE"];
    actions {
      add_header = 3;
    }
  }
}
operator_netblock {
  priority = high;
  ip = "198.51.100.0/24";
  apply {
    symbols_disabled = ["MISSING_DATE"];
  }
}
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
	write("local.d/settings.conf", operatorSettings)
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

// scopeRecord is a scan record: logged from CSM's Lua file, then the full
// grammar.
var scopeRecord = regexp.MustCompile(`; lua; csm_scope\.lua:[0-9]+: CSM-ANTISPAM (event=scan mode=(?:enforce|dry-run) policy=(?:on|off) result=ok score=(-?[0-9]+) action="[a-z_ ]*" decision=(?:unfiltered|reject|tag|none) ip=[0-9a-f.:]* qid=[0-9A-Za-z_]*)$`)

func (r *scopeRspamd) check(t *testing.T, s Settings, c scopeCase) {
	t.Helper()
	r.scans++
	qid := fmt.Sprintf("CSMSCOPE%02d", r.scans)
	msg := fmt.Sprintf("From: sender@example.net\r\nTo: user@example.com\r\nSubject: scope test\r\nX-Test-Score: %d\r\n", c.score)
	for _, header := range c.authHeaders {
		msg += "Authentication-Results: " + header + "\r\n"
	}
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
	if _, ok := reply.Symbols[c.has]; c.has != "" && !ok {
		t.Errorf("%s: reply lacks %s", c.name, c.has)
	}
	if _, ok := reply.Symbols[c.lacks]; ok {
		t.Errorf("%s: reply carries %s, which the operator's rule disables", c.name, c.lacks)
	}
	for action, limit := range c.limits {
		if got, ok := reply.Thresholds[action]; !ok || got != limit {
			t.Errorf("%s: %s threshold %v (set %t), want %v", c.name, action, got, ok, limit)
		}
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

	// Mail from the internet gets the host's own Authentication-Results and
	// loses any copy it arrived with. Authenticated and local mail keep
	// theirs and get none, so no login name reaches an outbound header.
	auth, arAdded := reply.Milter.Add["Authentication-Results"]
	arRemove, arRemoved := reply.Milter.Remove["Authentication-Results"]
	if c.keepAuth {
		if arAdded || arRemoved {
			t.Errorf("%s: milter changes Authentication-Results on authenticated or local mail: %s", c.name, out)
		}
	} else {
		if !arAdded || strings.TrimSpace(auth.Value) == "" {
			t.Errorf("%s: milter adds no Authentication-Results value: %s", c.name, out)
		}
		if !arRemoved || arRemove != 0 {
			t.Errorf("%s: milter does not remove every inbound Authentication-Results: %s", c.name, out)
		}
		if strings.Contains(auth.Value, "forged.example.") {
			t.Errorf("%s: milter repeats forged Authentication-Results: %q", c.name, auth.Value)
		}
	}
	if strings.Contains(auth.Value, "smtp.auth=") {
		t.Errorf("%s: Authentication-Results exposes an authenticated login: %q", c.name, auth.Value)
	}

	if c.lifted {
		for _, action := range []string{"reject", "add header"} {
			if got := reply.Thresholds[action]; got != 100000 {
				t.Errorf("%s: %s threshold %v, want CSM's 100000", c.name, action, got)
			}
		}
	}
	if c.kept || c.lifted {
		dumps := r.logged(t, qid, "CSM-TEST settings=")
		if len(dumps) != 1 {
			t.Fatalf("%s: %d settings dumps, want 1", c.name, len(dumps))
		}
		dump := dumps[0][strings.Index(dumps[0], "CSM-TEST settings=")+len("CSM-TEST settings="):]
		dump, _, _ = strings.Cut(dump, " qid=")
		var final struct {
			SymbolsDisabled []string           `json:"symbols_disabled"`
			Actions         map[string]float64 `json:"actions"`
		}
		if err := json.Unmarshal([]byte(dump), &final); err != nil {
			t.Fatalf("%s: settings dump %q: %v", c.name, dump, err)
		}
		if c.kept && !slices.Contains(final.SymbolsDisabled, "MISSING_DATE") {
			t.Errorf("%s: the operator's rule is gone from the task's settings: %s", c.name, dump)
		}
		for _, alias := range []string{"add_header", "rewrite_subject"} {
			if _, ok := final.Actions[alias]; c.lifted && ok {
				t.Errorf("%s: %s competes with CSM's limit in the task's settings: %s", c.name, alias, dump)
			}
		}
	}
	records := r.logged(t, qid, "CSM-ANTISPAM")
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
	// The daemon reads the line as rspamd wrote it, prefix included.
	wantScan := Scan{OK: true, Mode: mode, Policy: policy, Score: score, Decision: decision, MsgID: qid}
	if ip != "" {
		wantScan.IP = netip.MustParseAddr(ip)
	}
	if got, ok := ParseRspamdScan(records[0]); !ok || got != wantScan {
		t.Errorf("%s: ParseRspamdScan(%q) = %+v, %t; want %+v", c.name, records[0], got, ok, wantScan)
	}
}

// logged waits for rspamd's own log line for qid, which follows every line
// a symbol logs for it, and returns the lines naming qid that hold marker.
func (r *scopeRspamd) logged(t *testing.T, qid, marker string) []string {
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
			if strings.Contains(line, marker) && strings.Contains(line, qid) {
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

// When rspamd cannot build the infra_ips map, the scope Lua logs an error
// on every load instead of quietly enforcing on infra senders. The rendered
// Lua runs under rspamadm with rspamd_config and the logger stubbed.
func TestPostfixScopeReportsMissingInfraMap(t *testing.T) {
	if _, err := exec.LookPath("rspamadm"); err != nil {
		t.Skip("rspamadm is not on PATH")
	}
	s := defaults(false)
	s.Stack, s.ScopeNets = StackPostfix, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	files, err := RenderPostfix(s)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	lua := filepath.Join(dir, "csm_scope.lua")
	if err = os.WriteFile(lua, []byte(files[PostfixScopeLuaPath]), 0o600); err != nil {
		t.Fatal(err)
	}
	harness := filepath.Join(dir, "harness.lua")
	script := fmt.Sprintf(`
local errors = {}
package.loaded.rspamd_logger = {
  errx = function(_, f, ...) errors[#errors + 1] = string.format(f, ...) end,
  infox = function() end,
}
rspamd_config = {
  radix_from_ucl = function() return nil end,
  register_symbol = function() end,
  register_dependency = function() end,
}
dofile(%q)
print('errors: ' .. table.concat(errors, ' | '))
`, lua)
	if err = os.WriteFile(harness, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("rspamadm", "lua", "-b", harness).CombinedOutput()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "errors: csm_scope: ") || !strings.Contains(string(out), "infra_ips") {
		t.Fatalf("no error for a missing infra_ips map:\n%s", out)
	}
}
