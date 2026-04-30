package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailspool"
)

func TestScriptState_AppendAndPrune(t *testing.T) {
	s := newScriptState()
	now := time.Now()
	s.append(scriptEvent{At: now.Add(-90 * time.Minute), MsgID: "old", FromMismatch: true, AdditionalSignal: true})
	s.append(scriptEvent{At: now.Add(-30 * time.Minute), MsgID: "mid", FromMismatch: true, AdditionalSignal: true})
	s.append(scriptEvent{At: now, MsgID: "new", FromMismatch: true, AdditionalSignal: true})

	n := s.qualifyingCount(now.Add(-60*time.Minute), func(e scriptEvent) bool {
		return e.FromMismatch && e.AdditionalSignal
	})
	if n != 2 {
		t.Errorf("qualifyingCount within 60m = %d, want 2 (mid + new)", n)
	}
}

func TestScriptState_ActiveMsgsCap(t *testing.T) {
	s := newScriptState()
	s.maxActiveMsgs = 3
	now := time.Now()
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		s.recordActive(id, now)
		now = now.Add(time.Second)
	}
	if !s.activeMsgsCapped {
		t.Errorf("expected activeMsgsCapped = true after exceeding maxActiveMsgs")
	}
	if got := len(s.activeMsgs); got > 3 {
		t.Errorf("activeMsgs len = %d, want <= 3", got)
	}
}

func TestScriptState_ActiveMsgsRemove(t *testing.T) {
	s := newScriptState()
	s.recordActive("id1", time.Now())
	s.removeActive("id1")
	if _, ok := s.activeMsgs["id1"]; ok {
		t.Errorf("id1 should be gone after removeActive")
	}
}

func TestScriptState_SnapshotActiveMsgs(t *testing.T) {
	s := newScriptState()
	now := time.Now()
	s.recordActive("a", now)
	s.recordActive("b", now)

	msgIDs, capped := s.snapshotActiveMsgs()
	if len(msgIDs) != 2 || capped {
		t.Errorf("snapshot = (%v, %v), want 2 msgIDs and capped=false", msgIDs, capped)
	}
	// Mutating the returned slice must NOT affect internal state.
	msgIDs[0] = "BOGUS"
	if _, ok := s.activeMsgs["BOGUS"]; ok {
		t.Errorf("snapshot must return a copy")
	}
}

// PruneActiveMsgs is a perScriptWindow-level helper added alongside SweepIdle.
// It iterates retained scriptStates and prunes activeMsgs entries older than
// cutoff. Called by Flow E (O2) on the 5-min ticker so still-active scripts
// don't accumulate ghost activeMsgs whose corresponding messages have left
// the queue without a "Completed" log line being parsed.
func TestPerScriptWindow_PruneActiveMsgs(t *testing.T) {
	w := newPerScriptWindow()
	s1 := w.getOrCreate("k1:/")
	s2 := w.getOrCreate("k2:/")
	now := time.Now()
	s1.recordActive("old1", now.Add(-26*time.Hour))
	s1.recordActive("fresh1", now)
	s2.recordActive("old2", now.Add(-26*time.Hour))

	pruned := w.PruneActiveMsgs(now.Add(-25 * time.Hour))
	if pruned != 2 {
		t.Errorf("pruned = %d, want 2", pruned)
	}
	if _, ok := s1.activeMsgs["old1"]; ok {
		t.Errorf("old1 should be pruned")
	}
	if _, ok := s1.activeMsgs["fresh1"]; !ok {
		t.Errorf("fresh1 should remain")
	}
	if _, ok := s2.activeMsgs["old2"]; ok {
		t.Errorf("old2 should be pruned")
	}
}

func TestPerIPWindow_DistinctScriptCount(t *testing.T) {
	w := newPerIPWindow(64)
	now := time.Now()
	w.append("192.0.2.1", "scriptA", now)
	w.append("192.0.2.1", "scriptB", now)
	w.append("192.0.2.1", "scriptA", now) // duplicate; still 2 distinct
	w.append("192.0.2.2", "scriptC", now)

	n := w.distinctScriptsSince("192.0.2.1", now.Add(-time.Hour))
	if n != 2 {
		t.Errorf("distinctScriptsSince = %d, want 2", n)
	}
}

func TestPerIPWindow_SweepIdle(t *testing.T) {
	w := newPerIPWindow(64)
	w.append("192.0.2.1", "s", time.Now().Add(-2*time.Hour))
	w.append("192.0.2.2", "s", time.Now())
	n := w.SweepIdle(time.Now().Add(-time.Hour))
	if n != 1 {
		t.Errorf("SweepIdle dropped = %d, want 1", n)
	}
}

func TestPerAccountWindow_VolumeCountAndCooldown(t *testing.T) {
	w := newPerAccountWindow(5000)
	now := time.Now()
	for i := 0; i < 10; i++ {
		w.append("u", now.Add(-time.Duration(i)*time.Minute))
	}
	if got := w.volumeSince("u", now.Add(-time.Hour)); got != 10 {
		t.Errorf("volumeSince = %d, want 10", got)
	}

	if !w.shouldFire("u", now, 30*time.Minute) {
		t.Fatal("first call must fire")
	}
	if w.shouldFire("u", now.Add(time.Minute), 30*time.Minute) {
		t.Fatal("cooldown must suppress immediate re-fire")
	}
	if !w.shouldFire("u", now.Add(31*time.Minute), 30*time.Minute) {
		t.Fatal("after cooldown must fire again")
	}
}

func TestComputeSignals_FromMismatchAndPHPMailer(t *testing.T) {
	pol := newTestPolicies(t)
	auth := map[string]struct{}{"example.com": {}}
	h := emailspool.Headers{
		From:         "Spoof <attacker@spoofed.example>",
		ReplyTo:      "attacker@gmail.example",
		XPHPScript:   "rentvsloan.example.com/wp-admin/admin-ajax.php for 192.0.2.10",
		XMailer:      "PHPMailer 7.0.0",
		EnvelopeUser: "exampleuser",
	}
	sig := computeSignals(h, auth, pol)
	if !sig.FromMismatch {
		t.Error("FromMismatch expected")
	}
	if !sig.AdditionalSignal {
		t.Error("AdditionalSignal expected (Reply-To external + PHPMailer)")
	}
	if sig.SourceIP != "192.0.2.10" {
		t.Errorf("SourceIP = %q", sig.SourceIP)
	}
	if sig.ScriptKey != "rentvsloan.example.com:/wp-admin/admin-ajax.php" {
		t.Errorf("ScriptKey = %q", sig.ScriptKey)
	}
}

func TestComputeSignals_LegitContactForm_NoFromMismatch(t *testing.T) {
	pol := newTestPolicies(t)
	auth := map[string]struct{}{"example.com": {}}
	h := emailspool.Headers{
		From:       "Site <site@example.com>",
		ReplyTo:    "visitor@gmail.example",
		XPHPScript: "example.com/wp-admin/admin-ajax.php for 192.0.2.20",
		XMailer:    "PHPMailer 6.0",
	}
	sig := computeSignals(h, auth, pol)
	if sig.FromMismatch {
		t.Error("legit contact form must not set FromMismatch")
	}
	// Path 1 requires fromMismatch as a HARD precondition; AdditionalSignal
	// alone must not fire it.
	if sig.AdditionalSignal && sig.FromMismatch {
		t.Error("Path 1 trigger requires both")
	}
}

func TestComputeSignals_SubdomainOfAccountIsAuthorised(t *testing.T) {
	pol := newTestPolicies(t)
	auth := map[string]struct{}{"example.com": {}}
	h := emailspool.Headers{
		From:       "Mail <mail@sub.example.com>",
		XPHPScript: "sub.example.com/notify.php for 192.0.2.30",
	}
	sig := computeSignals(h, auth, pol)
	if sig.FromMismatch {
		t.Error("sub.example.com From must be authorised when example.com is in account")
	}
}

func defaultPHPRelayCfg() *config.Config {
	cfg := &config.Config{}
	cfg.EmailProtection.PHPRelay.Enabled = true
	cfg.EmailProtection.PHPRelay.RateWindowMin = 5
	cfg.EmailProtection.PHPRelay.HeaderScoreVolumeMin = 5
	cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour = 30
	cfg.EmailProtection.PHPRelay.FanoutDistinctScripts = 3
	cfg.EmailProtection.PHPRelay.FanoutWindowMin = 5
	return cfg
}

func TestEvaluatePaths_Path1_FiresOnSustainedQualifyingEvents(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	eng := newEvaluator(psw, pip, nil, cfg, nil)

	k := scriptKey("attacker.example.com:/admin-ajax.php")
	now := time.Now()
	// 5 qualifying events within 5 min (FromMismatch + AdditionalSignal).
	for i := 0; i < 5; i++ {
		psw.getOrCreate(k).append(scriptEvent{
			At:               now.Add(time.Duration(-i*30) * time.Second),
			MsgID:            "id" + string(rune('0'+i)),
			FromMismatch:     true,
			AdditionalSignal: true,
		})
	}

	findings := eng.evaluatePaths(k, "192.0.2.10", "exampleuser", now)
	foundHeader := false
	for _, f := range findings {
		if f.Path == "header" && f.Check == "email_php_relay_abuse" && f.Severity == alert.Critical {
			foundHeader = true
			if f.ScriptKey != string(k) {
				t.Errorf("ScriptKey = %q, want %q", f.ScriptKey, k)
			}
		}
	}
	if !foundHeader {
		t.Errorf("expected Path 1 finding, got %+v", findings)
	}
}

func TestEvaluatePaths_Path1_DoesNotFireWithoutFromMismatch(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	eng := newEvaluator(psw, pip, nil, cfg, nil)

	k := scriptKey("contact.example.com:/admin-ajax.php")
	now := time.Now()
	// 10 events with AdditionalSignal but NOT FromMismatch (legit form).
	for i := 0; i < 10; i++ {
		psw.getOrCreate(k).append(scriptEvent{
			At:               now.Add(time.Duration(-i*10) * time.Second),
			MsgID:            "x",
			FromMismatch:     false,
			AdditionalSignal: true,
		})
	}
	findings := eng.evaluatePaths(k, "192.0.2.20", "u", now)
	for _, f := range findings {
		if f.Path == "header" {
			t.Errorf("Path 1 must not fire without FromMismatch: %+v", f)
		}
	}
}

func TestEvaluatePaths_Path1_Cooldown(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	eng := newEvaluator(psw, pip, nil, cfg, nil)

	k := scriptKey("k:/p")
	now := time.Now()
	fill := func() {
		for i := 0; i < 5; i++ {
			psw.getOrCreate(k).append(scriptEvent{At: now, FromMismatch: true, AdditionalSignal: true})
		}
	}
	fill()
	if findings := eng.evaluatePaths(k, "", "u", now); len(findings) == 0 {
		t.Fatal("first call must fire")
	}
	// Immediate re-evaluation: cooldown suppresses.
	if findings := eng.evaluatePaths(k, "", "u", now); len(findings) != 0 {
		t.Errorf("cooldown must suppress immediate re-fire, got %+v", findings)
	}
}

func TestEvaluatePaths_Path2_FiresOnAbsoluteVolume(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.AbsoluteVolumePerHour = 5 // tight for test
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	eng := newEvaluator(psw, pip, nil, cfg, nil)

	k := scriptKey("k:/p")
	now := time.Now()
	// 6 events in last hour, but NONE qualify Path 1 (no FromMismatch).
	for i := 0; i < 6; i++ {
		psw.getOrCreate(k).append(scriptEvent{
			At:               now.Add(time.Duration(-i*10) * time.Minute),
			FromMismatch:     false,
			AdditionalSignal: false,
		})
	}
	findings := eng.evaluatePaths(k, "", "u", now)
	foundVolume := false
	for _, f := range findings {
		if f.Path == "volume" {
			foundVolume = true
		}
		if f.Path == "header" {
			t.Errorf("Path 1 must not fire here: %+v", f)
		}
	}
	if !foundVolume {
		t.Errorf("Path 2 expected, got %+v", findings)
	}
}

// newTestPolicies returns a Policies with PHPMailer suspicious + WordPress safe.
func newTestPolicies(t *testing.T) *emailspool.Policies {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/mailer_classes.yaml", []byte(`version: 1
suspicious: [phpmailer]
safe: [wordpress, cpanel]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, err := emailspool.LoadPolicies(dir)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func TestEvaluatePaths_Path4_FiresOnFanout(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.FanoutDistinctScripts = 3
	cfg.EmailProtection.PHPRelay.FanoutWindowMin = 5
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	eng := newEvaluator(psw, pip, nil, cfg, nil)

	now := time.Now()
	pip.append("192.0.2.99", "kA:/", now)
	pip.append("192.0.2.99", "kB:/", now)
	pip.append("192.0.2.99", "kC:/", now)

	findings := eng.evaluatePaths("kC:/", "192.0.2.99", "u", now)
	foundFanout := false
	for _, f := range findings {
		if f.Path == "fanout" {
			foundFanout = true
			if f.SourceIP != "192.0.2.99" {
				t.Errorf("SourceIP = %q", f.SourceIP)
			}
		}
	}
	if !foundFanout {
		t.Errorf("Path 4 expected, got %+v", findings)
	}
}

func TestEvaluatePaths_Path4_SkipsProxyIPs(t *testing.T) {
	cfg := defaultPHPRelayCfg()
	psw := newPerScriptWindow()
	pip := newPerIPWindow(64)
	pol := newTestPoliciesWithProxy(t, "192.0.2.0/24")
	eng := newEvaluator(psw, pip, nil, cfg, nil)
	eng.policies = pol

	now := time.Now()
	pip.append("192.0.2.99", "kA:/", now)
	pip.append("192.0.2.99", "kB:/", now)
	pip.append("192.0.2.99", "kC:/", now)

	findings := eng.evaluatePaths("kC:/", "192.0.2.99", "u", now)
	for _, f := range findings {
		if f.Path == "fanout" {
			t.Errorf("Path 4 must skip proxy IPs: %+v", f)
		}
	}
}

func newTestPoliciesWithProxy(t *testing.T, cidr string) *emailspool.Policies {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/http_proxy_ranges.yaml", []byte("version: 1\ncidrs: [\""+cidr+"\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, err := emailspool.LoadPolicies(dir)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func TestReadCpanelHourlyLimit_Parses(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cpanel.config")
	_ = os.WriteFile(cfgPath, []byte("foo=bar\nmaxemailsperhour=200\nbaz=qux\n"), 0o644)

	got, status := readCpanelHourlyLimit(cfgPath)
	if got != 200 || status != cpanelLimitOK {
		t.Errorf("readCpanelHourlyLimit = (%d, %v), want (200, OK)", got, status)
	}
}

func TestReadCpanelHourlyLimit_Missing(t *testing.T) {
	got, status := readCpanelHourlyLimit("/nonexistent/path")
	if status != cpanelLimitMissing {
		t.Errorf("status = %v, want missing", status)
	}
	if got != 0 {
		t.Errorf("missing must return 0 hint, got %d", got)
	}
}

func TestReadCpanelHourlyLimit_Zero_DisabledByOperator(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cpanel.config")
	_ = os.WriteFile(cfgPath, []byte("maxemailsperhour=0\n"), 0o644)
	got, status := readCpanelHourlyLimit(cfgPath)
	if status != cpanelLimitDisabled || got != 0 {
		t.Errorf("readCpanelHourlyLimit = (%d, %v), want (0, disabled)", got, status)
	}
}

func TestReadCpanelHourlyLimit_Unparsable(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cpanel.config")
	_ = os.WriteFile(cfgPath, []byte("maxemailsperhour=banana\n"), 0o644)
	_, status := readCpanelHourlyLimit(cfgPath)
	if status != cpanelLimitUnparsable {
		t.Errorf("status = %v, want unparsable", status)
	}
}
