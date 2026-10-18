package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/admissionowner"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/verdict"
)

func publishTestConfig(t *testing.T, body string) *config.Config {
	t.Helper()
	cfg, err := config.LoadBytes([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	config.SetActive(cfg)
	return cfg
}

// verdictServer answers every callback with verdict and records the
// requests it saw.
func verdictServer(t *testing.T, answer string) (*httptest.Server, func() []verdict.Request) {
	t.Helper()
	var mu sync.Mutex
	var seen []verdict.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req verdict.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		mu.Lock()
		seen = append(seen, req)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"verdict":"` + answer + `"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []verdict.Request {
		mu.Lock()
		defer mu.Unlock()
		return append([]verdict.Request(nil), seen...)
	}
}

// D11: the daemon reads the execution policy from one publication: the
// mode, the dry-run default when the key is omitted, the callback and its
// timeout, the ceiling and the lifetimes, under the publication's epoch.
// An asker keeps the callback it was built with after a later publication.
func TestExecutionPolicyFollowsThePublishedConfig(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	d := &Daemon{}
	cfg := publishTestConfig(t, "auto_response:\n  max_blocks_per_hour: 120\n  block_expiry: 2h\n")
	p := d.executionPolicy()
	if _, epoch := config.ActiveEpoch(); p.Epoch != epoch || epoch == 0 {
		t.Fatalf("policy epoch %d, published %d", p.Epoch, epoch)
	}
	scan := admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP}, Entry: admission.EntryScan}
	if !p.DryRun || p.Observe || p.VerdictEnabled || p.VerdictTimeout != 2*time.Second || p.CeilingLimit != 120 ||
		p.CeilingSource != config.CeilingConfigured || p.Expiry == nil || p.Expiry(scan) != 2*time.Hour || p.AskVerdict == nil {
		t.Fatalf("policy from %+v = %+v", cfg.AutoResponse, p)
	}
	first, firstSeen := verdictServer(t, "block")
	second, secondSeen := verdictServer(t, "")
	callback := func(url string) string {
		return "auto_response:\n  dry_run: false\n  verdict_callback:\n    enabled: true\n    url: " + url + "\n    timeout_sec: 5\n    allow_unsigned: true\n"
	}
	publishTestConfig(t, callback(first.URL))
	live := d.executionPolicy()
	if live.Epoch <= p.Epoch || live.DryRun || !live.VerdictEnabled || live.VerdictTimeout != 5*time.Second {
		t.Fatalf("live policy = %+v", live)
	}
	publishTestConfig(t, callback(second.URL))
	resp, err := live.AskVerdict(context.Background(), "192.0.2.10", "CSM auto-block: ssh_brute")
	if err != nil || resp.Verdict != "block" {
		t.Fatalf("asker = %+v, %v", resp, err)
	}
	if got := firstSeen(); len(got) != 1 || got[0].IP != "192.0.2.10" || got[0].Reason != "CSM auto-block: ssh_brute" || got[0].Source != "auto_response" {
		t.Fatalf("first callback saw %+v", got)
	}
	if got := secondSeen(); len(got) != 0 {
		t.Fatalf("an asker followed a later publication: %+v", got)
	}
	observe := publishTestConfig(t, "mode: observe\n")
	if p := d.executionPolicy(); !p.Observe || p.Epoch <= live.Epoch {
		t.Fatalf("observe policy from %q = %+v", observe.Mode, p)
	}
}

// The policy allows what the published switches allow, through the same
// rule the legacy funnels apply, and keeps the configuration it was built
// with after a later publication.
func TestExecutionPolicyAllowsWhatTheConfigAllows(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	d := &Daemon{}
	block := func(check string) admission.Candidate {
		return admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP}, Entry: admission.EntryScan, Check: check}
	}
	publishTestConfig(t, "auto_response:\n  enabled: true\n  block_ips: true\n")
	on := d.executionPolicy()
	if on.Allows == nil || !on.Allows(block("ftp_bruteforce")) || on.Allows(block("cpanel_multi_ip_login")) {
		t.Fatal("the policy does not follow the block switches")
	}
	publishTestConfig(t, "auto_response:\n  enabled: false\n  block_ips: true\n")
	if off := d.executionPolicy(); off.Allows(block("ftp_bruteforce")) {
		t.Fatal("a policy with blocking off allows a block")
	}
	if !on.Allows(block("ftp_bruteforce")) {
		t.Fatal("an earlier policy followed a later publication")
	}
}

// The owner's refusal of a published policy reaches the reload health
// path as a config_reload_error finding.
func TestDaemonReportsARefusedExecutionPolicy(t *testing.T) {
	dir := t.TempDir()
	db, restore := openTestBoltStore(t, dir)
	defer restore()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	cfg := publishTestConfig(t, "auto_response:\n  dry_run: false\n")
	cfg.StatePath = dir
	d := New(cfg, st, nil, "")
	d.alertCh = make(chan alert.Finding, 4)
	opts := testAdmissionOptions(d, db)
	opts.Blocks = func() admissionowner.BlockEngine { return nil }
	d.startAdmissionWith(opts)
	defer d.stopAdmission()
	if st := d.AdmissionStatus(); st.Owner.Error != "" {
		t.Fatalf("owner = %+v", st.Owner)
	}
	d.reloadAdmission()
	if len(d.alertCh) != 0 {
		t.Fatalf("a valid policy was reported: %+v", <-d.alertCh)
	}
	publishTestConfig(t, "mode: observe\n")
	d.reloadAdmission()
	if len(d.alertCh) != 1 {
		t.Fatalf("%d findings for a refused policy", len(d.alertCh))
	}
	f := <-d.alertCh
	if f.Check != "config_reload_error" || f.Severity != alert.Critical || !strings.Contains(f.Message, admissionowner.ErrPolicy.Error()) {
		t.Fatalf("finding = %+v", f)
	}
	if held := d.AdmissionStatus().Owner.ExecutionHeld; !strings.Contains(held, "mode: observe") {
		t.Fatalf("execution held = %q", held)
	}
}
