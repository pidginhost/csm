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
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/verdict"
)

func noRoots() []admission.Evidence { return nil }

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
		p.CeilingSource != config.CeilingConfigured || p.Expiry == nil || p.Expiry(scan) != 2*time.Hour || p.BlockExpiry != 2*time.Hour || p.AskVerdict == nil {
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
	if p.BlockExpiry != 2*time.Hour || p.Expiry(scan) != 2*time.Hour || live.BlockExpiry != 24*time.Hour {
		t.Fatalf("earlier policies changed after publication: first=%v live=%v", p.BlockExpiry, live.BlockExpiry)
	}
	publishTestConfig(t, "auto_response:\n  block_expiry: 30m\n")
	shorter := d.executionPolicy()
	if shorter.Epoch <= live.Epoch || shorter.BlockExpiry != 30*time.Minute || shorter.Expiry(scan) != 30*time.Minute {
		t.Fatalf("new policy did not carry the new lease: %+v", shorter)
	}
	if p.BlockExpiry != 2*time.Hour || live.BlockExpiry != 24*time.Hour || live.Expiry(scan) != 24*time.Hour {
		t.Fatal("new lease changed an earlier publication")
	}
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
// rule the legacy funnels apply, and follows a later publication.
func TestExecutionPolicyAllowsWhatTheConfigAllows(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	d := &Daemon{}
	block := func(check string) admission.Candidate {
		return admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP}, Entry: admission.EntryScan, Check: check}
	}
	publishTestConfig(t, "auto_response:\n  enabled: true\n  block_ips: true\n")
	on := d.executionPolicy()
	if on.Allows == nil || !on.Allows(block("ftp_bruteforce"), noRoots) || on.Allows(block("cpanel_multi_ip_login"), noRoots) {
		t.Fatal("the policy does not follow the block switches")
	}
	publishTestConfig(t, "auto_response:\n  enabled: false\n  block_ips: true\n")
	if off := d.executionPolicy(); off.Allows(block("ftp_bruteforce"), noRoots) {
		t.Fatal("a policy with blocking off allows a block")
	}
	if on.Allows(block("ftp_bruteforce"), noRoots) {
		t.Fatal("an earlier policy allows a block the live config forbids")
	}
}

// A save that changes no auto_response setting publishes no new epoch, so
// the owner keeps its installed policy. Queued work must still follow the
// saved switches: a challenge timeout block after challenges are turned
// off, or an incident block after incident blocking is.
func TestExecutionPolicyFollowsSettingsOutsideItsEpoch(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	d := &Daemon{}
	base := "auto_response:\n  enabled: true\n  block_ips: true\n"
	on := base + "challenge:\n  enabled: true\nincidents:\n  auto_block:\n    enabled: true\n    block_at_severity: high\n"
	off := base + "challenge:\n  enabled: false\nincidents:\n  auto_block:\n    enabled: false\n    block_at_severity: high\n"
	publishTestConfig(t, on)
	p := d.executionPolicy()
	for _, entry := range []admission.Entry{admission.EntryChallengeTimeout, admission.EntryIncident} {
		if !p.Allows(admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP}, Entry: entry, Check: "wp_login_bruteforce"}, noRoots) {
			t.Fatalf("policy refuses %v while it is on", entry)
		}
	}
	publishTestConfig(t, off)
	if _, epoch := config.ActiveEpoch(); epoch != p.Epoch {
		t.Fatalf("the save moved the epoch from %d to %d", p.Epoch, epoch)
	}
	for _, entry := range []admission.Entry{admission.EntryChallengeTimeout, admission.EntryIncident} {
		if p.Allows(admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP}, Entry: entry, Check: "wp_login_bruteforce"}, noRoots) {
			t.Fatalf("installed policy still allows %v after it was turned off", entry)
		}
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

// A queued block of an address the saved config now names as a trusted
// proxy is refused at the next turn, without a new epoch.
func TestExecutionPolicyRefusesQueuedBlocksOfANewTrustedProxy(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	d := &Daemon{}
	base := "auto_response:\n  enabled: true\n  block_ips: true\n"
	publishTestConfig(t, base)
	p := d.executionPolicy()
	target, err := admission.CanonicalAddress("192.0.2.44", admission.Caps{IPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	c := admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP, Target: target}, Entry: admission.EntryScan, Check: "ftp_bruteforce"}
	if !p.Allows(c, noRoots) {
		t.Fatal("policy refuses an ordinary queued block")
	}
	publishTestConfig(t, base+"web_server:\n  trusted_proxies: [\"192.0.2.44\"]\n")
	if _, epoch := config.ActiveEpoch(); epoch != p.Epoch {
		t.Fatalf("the save moved the epoch from %d to %d", p.Epoch, epoch)
	}
	if p.Allows(c, noRoots) {
		t.Fatal("installed policy allows a queued block of a trusted proxy")
	}
}

// The daemon keeps a nonpositive block_expiry as written; the owner's
// policy validation refuses it, so such an owner never executes blocks.
// An empty or unparsable value falls back to 24 hours.
func TestExecutionPolicyLeaseParsingBoundary(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	base, err := config.LoadBytes([]byte("auto_response:\n  enabled: true\n  block_ips: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{}
	scan := admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP}, Entry: admission.EntryScan}
	for _, tc := range []struct {
		setting string
		want    time.Duration
	}{{"", 24 * time.Hour}, {"invalid", 24 * time.Hour}, {"1h", time.Hour}, {"0s", 0}, {"-1h", -time.Hour}} {
		cfg := *base
		cfg.AutoResponse.BlockExpiry = tc.setting
		config.SetActive(&cfg)
		p := d.executionPolicy()
		if p.BlockExpiry != tc.want || p.Expiry(scan) != tc.want {
			t.Errorf("block_expiry %q: lease %s, scan expiry %s; want %s", tc.setting, p.BlockExpiry, p.Expiry(scan), tc.want)
		}
	}
}

// Central intel, incident spray suppression and a detector's own mode also
// change without a new epoch. An installed policy follows each of them off
// and back on.
func TestExecutionPolicyFollowsCentralSprayAndDetectorModes(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	base, err := config.LoadBytes([]byte("auto_response:\n  enabled: true\n  block_ips: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{}
	block := func(entry admission.Entry, check string) admission.Candidate {
		return admission.Candidate{Key: admission.CandidateKey{Kind: admission.KindBlockIP}, Entry: entry, Check: check}
	}
	for _, tc := range []struct {
		name string
		c    admission.Candidate
		set  func(cfg *config.Config, on bool)
	}{
		{"central", block(admission.EntryCentral, "ftp_bruteforce"), func(cfg *config.Config, on bool) {
			cfg.Reputation.Central.Enabled = on
			cfg.Reputation.Central.Action = "block_if_local_corroborated"
		}},
		{"incident_spray", block(admission.EntryIncidentSpray, "ftp_bruteforce"), func(cfg *config.Config, on bool) {
			cfg.Incidents.SpraySuppression.Enabled = on
			cfg.Incidents.SpraySuppression.DryRun = false
			cfg.Incidents.SpraySuppression.BlockAtSeverity = "high"
		}},
		{"detector mode", block(admission.EntryScan, "email_php_form_relay"), func(cfg *config.Config, on bool) {
			cfg.EmailProtection.PHPRelay.IPRecipientMode = map[bool]string{true: "enforce", false: "observe"}[on]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publish := func(on bool) {
				cfg := *base
				tc.set(&cfg, on)
				config.SetActive(&cfg)
			}
			publish(true)
			p := d.executionPolicy()
			if !p.Allows(tc.c, noRoots) {
				t.Fatal("policy refuses the response while it is on")
			}
			publish(false)
			if _, epoch := config.ActiveEpoch(); epoch != p.Epoch {
				t.Fatalf("the save moved the epoch from %d to %d", p.Epoch, epoch)
			}
			if p.Allows(tc.c, noRoots) {
				t.Fatal("installed policy still allows the response after it was turned off")
			}
			publish(true)
			if !p.Allows(tc.c, noRoots) {
				t.Fatal("installed policy refuses the response after it was turned back on")
			}
		})
	}
}

// A queued central block whose source is turned off ends refused as
// disabled when the owner next serves its queue: no attempt, no engine
// call, no notice and no ceiling charge.
func TestExecutionPolicyDisablesQueuedCentralBlock(t *testing.T) {
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
	base, err := config.LoadBytes([]byte("auto_response:\n  enabled: true\n  block_ips: true\n  dry_run: false\nreputation:\n  central:\n    enabled: true\n    action: block_if_local_corroborated\n"))
	if err != nil {
		t.Fatal(err)
	}
	base.StatePath = dir
	config.SetActive(base)
	d := New(base, st, nil, "")
	epochBeforeSave := d.executionPolicy().Epoch
	opts := testAdmissionOptions(d, db)
	// An executable owner with no engine yet: nothing can reach an engine.
	opts.Blocks = func() admissionowner.BlockEngine { return nil }
	d.startAdmissionWith(opts)
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	f := alert.Finding{
		Severity: alert.Critical, Check: "ftp_bruteforce", SourceIP: "203.0.113.71", Timestamp: now,
		Attribution: admission.AttributionPeer,
		Observation: alert.Observation{Producer: string(checks.ProducerFTPJournal), Stream: "f:1:2", Cursor: "0:0123456789abcdef", ObservedAt: now},
	}
	root, err := d.admission.Mint(f)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err = d.admission.Respond(admission.KindBlockIP, "203.0.113.71", root, admission.EntryCentral, 24*time.Hour); err != nil {
		t.Fatalf("respond: %v", err)
	}
	// Stopping drains the accepted request into the queue; the next owner
	// starts on the same settings and leaves it queued.
	d.stopAdmission()
	d.admission = nil
	d.startAdmissionWith(opts)
	defer d.stopAdmission()
	d.reloadAdmission()
	if ls := d.AdmissionStatus().Ledger; ls == nil || ls.Queue.Queued != 1 {
		t.Fatalf("queued central block missing before the save: %+v", ls)
	}
	off := *base
	off.Reputation.Central.Enabled = false
	config.SetActive(&off)
	if _, epoch := config.ActiveEpoch(); epoch != epochBeforeSave {
		t.Fatalf("the save moved the epoch from %d to %d", epochBeforeSave, epoch)
	}
	d.reloadAdmission()
	ls := d.AdmissionStatus().Ledger
	if ls == nil {
		t.Fatal("no ledger status")
	}
	disabled := uint64(0)
	for _, r := range ls.Counters.Rows {
		if r.Reason == "disabled" {
			disabled += r.N
		}
	}
	if disabled != 1 || ls.Queue.Queued != 0 || ls.Queue.Reserved != 0 || ls.Queue.Executing != 0 || ls.Queue.Retrying != 0 {
		t.Fatalf("queue %+v, disabled endings %d; want the central block ended disabled", ls.Queue, disabled)
	}
	if ls.Ceiling.General.Used != 0 || ls.Ceiling.Reserved.Used != 0 || len(ls.Notices.Records) != 0 {
		t.Fatalf("ceiling %+v, notices %+v; want no charge and no notice", ls.Ceiling, ls.Notices.Records)
	}
}
