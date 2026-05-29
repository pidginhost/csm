package daemon

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

func resetEmailRateState() {
	emailRateWindows = sync.Map{}
	emailRateSuppressed = struct {
		mu      sync.Mutex
		domains map[string]time.Time
	}{domains: make(map[string]time.Time)}
}

func withGlobalStore(t *testing.T, fn func(db *store.DB)) {
	t.Helper()

	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	prev := store.Global()
	store.SetGlobal(db)
	defer store.SetGlobal(prev)

	fn(db)
}

func testEmailProtectionConfig() *config.Config {
	cfg := &config.Config{}
	cfg.EmailProtection.RateWarnThreshold = 2
	cfg.EmailProtection.RateCritThreshold = 3
	cfg.EmailProtection.RateWindowMin = 10
	return cfg
}

func TestParseSessionLogLine_DirectLogin(t *testing.T) {
	resetPurgeTrackerState()

	cfg := &config.Config{}
	line := `2026-04-11T12:00:00Z [cpaneld] 198.51.100.20 NEW alice:session method=handle_form_login`

	findings := parseSessionLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "cpanel_login_realtime" {
		t.Fatalf("check = %q, want cpanel_login_realtime", findings[0].Check)
	}
	if !purgeTracker.isPostPurge401("198.51.100.20") {
		purgeTracker.recordPurge("alice")
		if !purgeTracker.isPostPurge401("198.51.100.20") {
			t.Fatal("direct login should record IP-to-account correlation for purge suppression")
		}
	}
}

func TestParseSessionLogLine_PortalSessionSuppressed(t *testing.T) {
	resetPurgeTrackerState()

	cfg := &config.Config{}
	line := `2026-04-11T12:00:00Z [cpaneld] 198.51.100.21 NEW alice:session method=create_user_session`

	findings := parseSessionLogLine(line, cfg)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for portal-created session, got %v", findings)
	}
}

func TestParseSessionLogLine_SuppressedByConfig(t *testing.T) {
	resetPurgeTrackerState()

	cfg := &config.Config{}
	cfg.Suppressions.SuppressCpanelLogin = true
	line := `2026-04-11T12:00:00Z [cpaneld] 198.51.100.22 NEW alice:session method=handle_form_login`

	findings := parseSessionLogLine(line, cfg)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when cPanel login suppression is enabled, got %v", findings)
	}
}

func TestParseSessionLogLine_PasswordPurge(t *testing.T) {
	resetPurgeTrackerState()

	cfg := &config.Config{}
	line := `2026-04-11T12:00:00Z [cpaneld] PURGE alice:password_change`

	findings := parseSessionLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "cpanel_password_purge_realtime" {
		t.Fatalf("check = %q, want cpanel_password_purge_realtime", findings[0].Check)
	}
}

func TestParseSecureLogLine_AcceptedSSHLogin(t *testing.T) {
	cfg := &config.Config{}
	line := `Apr 11 12:00:00 host sshd[12345]: Accepted password for root from 198.51.100.30 port 54321 ssh2`

	findings := parseSecureLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "ssh_login_realtime" {
		t.Fatalf("check = %q, want ssh_login_realtime", findings[0].Check)
	}
}

func TestParseSecureLogLine_IgnoresInfraAndLoopback(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"198.51.100.31/32"}}

	infraLine := `Apr 11 12:00:00 host sshd[12345]: Accepted password for root from 198.51.100.31 port 54321 ssh2`
	if findings := parseSecureLogLine(infraLine, cfg); len(findings) != 0 {
		t.Fatalf("infra IP should be ignored, got %v", findings)
	}

	loopbackLine := `Apr 11 12:00:00 host sshd[12345]: Accepted password for root from 127.0.0.1 port 54321 ssh2`
	if findings := parseSecureLogLine(loopbackLine, cfg); len(findings) != 0 {
		t.Fatalf("loopback IP should be ignored, got %v", findings)
	}
}

func TestParseEximLogLine_FrozenMessage(t *testing.T) {
	cfg := &config.Config{}
	line := `2026-04-11 12:00:00 1abc23-000456-AB frozen`

	findings := parseEximLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "exim_frozen_realtime" {
		t.Fatalf("check = %q, want exim_frozen_realtime", findings[0].Check)
	}
}

func TestParseEximLogLine_CredentialLeakInSubject(t *testing.T) {
	cfg := &config.Config{}
	line := `2026-04-11 12:00:00 1abc23-000456-AB <= sender@example.com H=mail.example.com [203.0.113.42] P=esmtpsa X=TLS1.3 A=dovecot_login:sender@example.com S=1234 T="smtp.example.com:587,user@example.com,SuperSecretPassword"`

	findings := parseEximLogLine(line, cfg)
	if len(findings) == 0 {
		t.Fatalf("expected credential leak findings, got none")
	}
	foundCritical := false
	for _, f := range findings {
		if f.Check == "email_credential_leak" && strings.Contains(f.Message, "SMTP credentials leaked") {
			foundCritical = true
			break
		}
	}
	if !foundCritical {
		t.Fatalf("expected critical SMTP credential leak finding, got %v", findings)
	}
}

func TestParseEximLogLine_DovecotAuthFailure(t *testing.T) {
	cfg := &config.Config{}
	line := `2026-04-11 12:00:00 dovecot_login authenticator failed for H=(mail.example.com) [198.51.100.40]:54321: 535 Incorrect authentication data (set_id=user@example.com)`

	findings := parseEximLogLine(line, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Check != "email_auth_failure_realtime" {
		t.Fatalf("check = %q, want email_auth_failure_realtime", findings[0].Check)
	}
}

func TestParseEximLogLine_OutgoingMailHoldDedup(t *testing.T) {
	withGlobalStore(t, func(db *store.DB) {
		cfg := &config.Config{}
		line := `2026-04-11 12:00:00 Sender office@example.com has an outgoing mail hold`

		first := parseEximLogLine(line, cfg)
		if len(first) != 1 {
			t.Fatalf("expected first hold line to alert once, got %d: %v", len(first), first)
		}
		if first[0].Check != "email_compromised_account" {
			t.Fatalf("check = %q, want email_compromised_account", first[0].Check)
		}

		second := parseEximLogLine(line, cfg)
		if len(second) != 0 {
			t.Fatalf("expected second hold line to be deduped, got %v", second)
		}

		if got := db.GetMetaString("email_hold:example.com"); got == "" {
			t.Fatal("expected dedup marker to be written to store")
		}
	})
}

// TestParseEximLogLine_OutgoingMailHoldDoesNotReapplyHold guards against
// the feedback loop where cPanel sets OUTGOING_MAIL_HOLD on a domain whose
// outbound mail happens to land on a few unreachable upstream prefixes,
// every queued retry then logs "Domain X has an outgoing mail hold"
// through exim's enforce_mail_permissions router, and CSM amplifies each
// retry by calling `whmapi1 hold_outgoing_email` again -- so an operator
// who clears the false-positive hold sees it reappear within seconds.
//
// cPanel's TailWatch::Eximstats is the authoritative source for these
// holds. CSM must alert on the rejection (so the operator sees the
// account is held) without re-issuing the hold itself.
func TestParseEximLogLine_OutgoingMailHoldDoesNotReapplyHold(t *testing.T) {
	withGlobalStore(t, func(_ *store.DB) {
		prevHook := autoSuspendOutgoingMail
		var suspendCalls []string
		var mu sync.Mutex
		autoSuspendOutgoingMail = func(target string) bool {
			mu.Lock()
			suspendCalls = append(suspendCalls, target)
			mu.Unlock()
			return true
		}
		t.Cleanup(func() { autoSuspendOutgoingMail = prevHook })

		cfg := &config.Config{}
		line := `2026-04-11 12:00:00 Sender office@example.com has an outgoing mail hold`

		findings := parseEximLogLine(line, cfg)
		if len(suspendCalls) != 0 {
			t.Fatalf("autoSuspendOutgoingMail invoked %d time(s) from the outgoing-mail-hold rejection path: %v -- re-applying the hold causes a feedback loop against operator-cleared false positives", len(suspendCalls), suspendCalls)
		}
		if len(findings) != 1 || findings[0].Check != "email_compromised_account" {
			t.Fatalf("expected one email_compromised_account finding, got %v", findings)
		}
	})
}

// eximAutoHoldConfig returns a config that opts in to live mail holds:
// auto-response enabled and dry-run explicitly off. Outgoing-mail holds are
// a customer-impacting auto-response action, so they require the same master
// switch + dry-run gate as IP blocks and quarantine.
func eximAutoHoldConfig() *config.Config {
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	dryRun := false
	cfg.AutoResponse.DryRun = &dryRun
	return cfg
}

// TestMaybeHoldOutgoingMail_GatedByConfig verifies the customer-impacting
// mail hold runs only when auto-response is enabled and dry-run is off, and
// is otherwise suppressed (the safety default).
func TestMaybeHoldOutgoingMail_GatedByConfig(t *testing.T) {
	prevHook := autoSuspendOutgoingMail
	var calls int
	autoSuspendOutgoingMail = func(string) bool { calls++; return true }
	t.Cleanup(func() { autoSuspendOutgoingMail = prevHook })

	dryRunOff := false
	dryRunOn := true
	enabled := &config.Config{}
	enabled.AutoResponse.Enabled = true
	enabled.AutoResponse.DryRun = &dryRunOff
	enabledDry := &config.Config{}
	enabledDry.AutoResponse.Enabled = true
	enabledDry.AutoResponse.DryRun = &dryRunOn

	cases := []struct {
		name     string
		cfg      *config.Config
		wantCall bool
	}{
		{"nil config", nil, false},
		{"defaults (disabled + dry-run)", &config.Config{}, false},
		{"enabled but dry-run", enabledDry, false},
		{"enabled and live", enabled, true},
	}
	for _, tc := range cases {
		calls = 0
		got := maybeHoldOutgoingMail(tc.cfg, "user@example.com")
		if got != tc.wantCall || (calls > 0) != tc.wantCall {
			t.Errorf("%s: held=%v calls=%d, want held=%v", tc.name, got, calls, tc.wantCall)
		}
	}
}

// TestParseEximLogLine_MaxDefersDryRunDoesNotHold asserts that with the safety
// defaults (auto-response disabled, dry-run on) a spam-outbreak line surfaces
// the finding for the operator but does NOT hold the customer's mail.
func TestParseEximLogLine_MaxDefersDryRunDoesNotHold(t *testing.T) {
	withGlobalStore(t, func(_ *store.DB) {
		prevHook := autoSuspendOutgoingMail
		var suspendCalls []string
		var mu sync.Mutex
		autoSuspendOutgoingMail = func(target string) bool {
			mu.Lock()
			suspendCalls = append(suspendCalls, target)
			mu.Unlock()
			return true
		}
		t.Cleanup(func() { autoSuspendOutgoingMail = prevHook })

		cfg := &config.Config{} // disabled + dry-run on (defaults)
		line := `2026-04-11 12:00:00 1abc23-000456-AB ** user@example.com R=enforce_mail_permissions : Domain example.com has exceeded the max defers and failures per hour (15/15 (100%)) allowed. Message discarded.`

		findings := parseEximLogLine(line, cfg)
		if len(suspendCalls) != 0 {
			t.Fatalf("auto-response disabled/dry-run must not hold mail; got calls %v", suspendCalls)
		}
		if len(findings) == 0 || findings[0].Check != "email_spam_outbreak" {
			t.Fatalf("outbreak finding must still surface for operator visibility; got %v", findings)
		}
	})
}

// TestParseEximLogLine_MaxDefersStillSuspends asserts that a max-defers
// threshold line still escalates when CSM has not recently seen cPanel hold
// the domain already.
func TestParseEximLogLine_MaxDefersStillSuspends(t *testing.T) {
	withGlobalStore(t, func(_ *store.DB) {
		prevHook := autoSuspendOutgoingMail
		var suspendCalls []string
		var mu sync.Mutex
		autoSuspendOutgoingMail = func(target string) bool {
			mu.Lock()
			suspendCalls = append(suspendCalls, target)
			mu.Unlock()
			return true
		}
		t.Cleanup(func() { autoSuspendOutgoingMail = prevHook })

		cfg := eximAutoHoldConfig()
		line := `2026-04-11 12:00:00 1abc23-000456-AB ** user@example.com R=enforce_mail_permissions : Domain example.com has exceeded the max defers and failures per hour (15/15 (100%)) allowed. Message discarded.`

		findings := parseEximLogLine(line, cfg)
		if len(suspendCalls) != 1 || suspendCalls[0] != "example.com" {
			t.Fatalf("autoSuspendOutgoingMail calls = %v, want one call with domain=example.com", suspendCalls)
		}
		if len(findings) == 0 || findings[0].Check != "email_spam_outbreak" {
			t.Fatalf("expected email_spam_outbreak finding, got %v", findings)
		}
	})
}

func TestParseEximLogLine_MaxDefersAfterRecentHoldDoesNotReportOutbreak(t *testing.T) {
	withGlobalStore(t, func(_ *store.DB) {
		prevHook := autoSuspendOutgoingMail
		var suspendCalls []string
		var mu sync.Mutex
		autoSuspendOutgoingMail = func(target string) bool {
			mu.Lock()
			suspendCalls = append(suspendCalls, target)
			mu.Unlock()
			return true
		}
		t.Cleanup(func() { autoSuspendOutgoingMail = prevHook })

		cfg := eximAutoHoldConfig()
		holdLine := `2026-04-11 12:00:00 1abc23-000456-AB == user@example.com R=enforce_mail_permissions defer (-1): "Domain example.com has an outgoing mail hold. Message will be reattempted later"`
		maxDefersLine := `2026-04-11 12:15:00 1abc23-000456-AB ** user@example.com R=enforce_mail_permissions : Domain example.com has exceeded the max defers and failures per hour (15/15 (100%)) allowed. Message discarded.`

		holdFindings := parseEximLogLine(holdLine, cfg)
		if len(holdFindings) != 1 || holdFindings[0].Check != "email_compromised_account" {
			t.Fatalf("expected hold finding before retry-limit line, got %v", holdFindings)
		}

		findings := parseEximLogLine(maxDefersLine, cfg)
		if len(findings) != 0 {
			t.Fatalf("expected held-domain retry-limit line to be suppressed, got %v", findings)
		}
		if len(suspendCalls) != 0 {
			t.Fatalf("autoSuspendOutgoingMail calls = %v, want none for held-domain retry-limit line", suspendCalls)
		}
	})
}

// TestParseEximLogLine_MaxDefersRecordsHoldDedup guards against the
// production feedback loop where every retry hour exim re-emits the
// "exceeded max defers/failures" line for an already-held domain and
// CSM re-invokes whmapi1 hold_outgoing_email per retry. The max-defers
// branch must record the hold-seen marker so subsequent identical lines
// fall through the existing 2-hour dedup window.
func TestParseEximLogLine_MaxDefersRecordsHoldDedup(t *testing.T) {
	withGlobalStore(t, func(db *store.DB) {
		prevHook := autoSuspendOutgoingMail
		var suspendCalls []string
		var mu sync.Mutex
		autoSuspendOutgoingMail = func(target string) bool {
			mu.Lock()
			suspendCalls = append(suspendCalls, target)
			mu.Unlock()
			return true
		}
		t.Cleanup(func() { autoSuspendOutgoingMail = prevHook })

		cfg := eximAutoHoldConfig()
		line := `2026-04-11 12:00:00 1abc23-000456-AB ** user@example.com R=enforce_mail_permissions : Domain example.com has exceeded the max defers and failures per hour (15/15 (100%)) allowed. Message discarded.`

		first := parseEximLogLine(line, cfg)
		if len(first) == 0 || first[0].Check != "email_spam_outbreak" {
			t.Fatalf("first max-defers line should fire spam outbreak, got %v", first)
		}
		if len(suspendCalls) != 1 {
			t.Fatalf("first call should auto-suspend once, got %d calls", len(suspendCalls))
		}
		if got := db.GetMetaString("email_hold_seen:example.com"); got == "" {
			t.Fatal("max-defers branch must record hold-seen marker for dedup")
		}

		second := parseEximLogLine(line, cfg)
		if len(second) != 0 {
			t.Fatalf("second identical max-defers line within window should be suppressed, got %v", second)
		}
		if len(suspendCalls) != 1 {
			t.Fatalf("second max-defers line must not re-invoke autoSuspendOutgoingMail, got %d calls", len(suspendCalls))
		}
	})
}

func TestParseEximLogLine_MaxDefersDoesNotRecordHoldDedupWhenSuspendFails(t *testing.T) {
	withGlobalStore(t, func(db *store.DB) {
		prevHook := autoSuspendOutgoingMail
		var suspendCalls []string
		var mu sync.Mutex
		autoSuspendOutgoingMail = func(target string) bool {
			mu.Lock()
			suspendCalls = append(suspendCalls, target)
			mu.Unlock()
			return false
		}
		t.Cleanup(func() { autoSuspendOutgoingMail = prevHook })

		cfg := eximAutoHoldConfig()
		line := `2026-04-11 12:00:00 1abc23-000456-AB ** user@example.com R=enforce_mail_permissions : Domain example.com has exceeded the max defers and failures per hour (15/15 (100%)) allowed. Message discarded.`

		first := parseEximLogLine(line, cfg)
		if len(first) == 0 || first[0].Check != "email_spam_outbreak" {
			t.Fatalf("first max-defers line should fire spam outbreak, got %v", first)
		}
		if got := db.GetMetaString("email_hold_seen:example.com"); got != "" {
			t.Fatalf("failed auto-suspend must not record hold-seen marker, got %q", got)
		}

		second := parseEximLogLine(line, cfg)
		if len(second) == 0 || second[0].Check != "email_spam_outbreak" {
			t.Fatalf("second max-defers line should still alert after failed auto-suspend, got %v", second)
		}
		if len(suspendCalls) != 2 {
			t.Fatalf("failed auto-suspend should be retried, got %d calls", len(suspendCalls))
		}
	})
}

// TestAutoSuspendOutgoingMail_SkipsWhenUserAlreadyHeld verifies that
// the helper does not invoke whmapi1 when /etc/outgoing_mail_hold_users
// already lists the cPanel user. This is the authoritative cPanel-side
// state and re-issuing the hold is a no-op that produces noise in
// monitor.log and triggers an unnecessary whmapi1 subprocess.
func TestAutoSuspendOutgoingMail_SkipsWhenUserAlreadyHeld(t *testing.T) {
	tmp := t.TempDir()

	udPath := tmp + "/userdomains"
	if err := os.WriteFile(udPath, []byte("example.com: holdy\n"), 0o644); err != nil {
		t.Fatalf("write userdomains: %v", err)
	}
	prevUD := userdomainsPath
	userdomainsPath = udPath
	t.Cleanup(func() { userdomainsPath = prevUD })

	holdPath := tmp + "/outgoing_mail_hold_users"
	if err := os.WriteFile(holdPath, []byte("holdy\nother\n"), 0o644); err != nil {
		t.Fatalf("write hold users: %v", err)
	}
	prevHP := outgoingMailHoldUsersPath
	outgoingMailHoldUsersPath = holdPath
	t.Cleanup(func() { outgoingMailHoldUsersPath = prevHP })

	var execCalls int
	prevExec := whmapi1HoldExec
	whmapi1HoldExec = func(_ string) ([]byte, error) {
		execCalls++
		return nil, nil
	}
	t.Cleanup(func() { whmapi1HoldExec = prevExec })

	if ok := autoSuspendOutgoingMailReal("example.com"); !ok {
		t.Fatal("already-held user should return success")
	}
	if execCalls != 0 {
		t.Fatalf("whmapi1 hold_outgoing_email must not run when user already on hold, got %d calls", execCalls)
	}

	if err := os.WriteFile(holdPath, []byte("other\n"), 0o644); err != nil {
		t.Fatalf("rewrite hold users: %v", err)
	}
	if ok := autoSuspendOutgoingMailReal("example.com"); !ok {
		t.Fatal("successful whmapi1 hold should return success")
	}
	if execCalls != 1 {
		t.Fatalf("whmapi1 hold_outgoing_email must run when user not yet held, got %d calls", execCalls)
	}
}

func TestAutoSuspendOutgoingMail_ReturnsFalseWhenHoldFails(t *testing.T) {
	tmp := t.TempDir()

	udPath := tmp + "/userdomains"
	if err := os.WriteFile(udPath, []byte("example.com: holdy\n"), 0o644); err != nil {
		t.Fatalf("write userdomains: %v", err)
	}
	prevUD := userdomainsPath
	userdomainsPath = udPath
	t.Cleanup(func() { userdomainsPath = prevUD })

	holdPath := tmp + "/outgoing_mail_hold_users"
	if err := os.WriteFile(holdPath, []byte("other\n"), 0o644); err != nil {
		t.Fatalf("write hold users: %v", err)
	}
	prevHP := outgoingMailHoldUsersPath
	outgoingMailHoldUsersPath = holdPath
	t.Cleanup(func() { outgoingMailHoldUsersPath = prevHP })

	prevExec := whmapi1HoldExec
	whmapi1HoldExec = func(_ string) ([]byte, error) {
		return []byte("denied"), os.ErrPermission
	}
	t.Cleanup(func() { whmapi1HoldExec = prevExec })

	if ok := autoSuspendOutgoingMailReal("example.com"); ok {
		t.Fatal("failed whmapi1 hold should return false")
	}
}

func TestParseEximLogLine_MaxDefersAfterStaleHoldStillSuspends(t *testing.T) {
	withGlobalStore(t, func(db *store.DB) {
		prevHook := autoSuspendOutgoingMail
		var suspendCalls []string
		var mu sync.Mutex
		autoSuspendOutgoingMail = func(target string) bool {
			mu.Lock()
			suspendCalls = append(suspendCalls, target)
			mu.Unlock()
			return true
		}
		t.Cleanup(func() { autoSuspendOutgoingMail = prevHook })

		stale := time.Now().Add(-recentOutgoingMailHoldWindow - time.Minute).Format(time.RFC3339)
		if err := db.SetMetaString("email_hold_seen:example.com", stale); err != nil {
			t.Fatalf("SetMetaString: %v", err)
		}

		cfg := eximAutoHoldConfig()
		line := `2026-04-11 12:00:00 1abc23-000456-AB ** user@example.com R=enforce_mail_permissions : Domain example.com has exceeded the max defers and failures per hour (15/15 (100%)) allowed. Message discarded.`

		findings := parseEximLogLine(line, cfg)
		if len(suspendCalls) != 1 || suspendCalls[0] != "example.com" {
			t.Fatalf("autoSuspendOutgoingMail calls = %v, want one call with domain=example.com", suspendCalls)
		}
		if len(findings) == 0 || findings[0].Check != "email_spam_outbreak" {
			t.Fatalf("expected email_spam_outbreak finding, got %v", findings)
		}
	})
}

func TestParseEximLogLine_EmailRateIntegration(t *testing.T) {
	resetEmailRateState()

	cfg := testEmailProtectionConfig()
	line := `2026-04-11 12:00:00 1abc23-000456-AB <= sender@example.com H=mail.example.com [203.0.113.42] P=esmtpsa X=TLS1.3 A=dovecot_login:sender@example.com S=1234 T="Normal subject"`

	if findings := parseEximLogLine(line, cfg); len(findings) != 0 {
		t.Fatalf("expected no findings below rate threshold, got %v", findings)
	}

	second := parseEximLogLine(line, cfg)
	if len(second) != 1 {
		t.Fatalf("expected warning finding at threshold, got %d: %v", len(second), second)
	}
	if second[0].Check != "email_rate_warning" {
		t.Fatalf("check = %q, want email_rate_warning", second[0].Check)
	}

	third := parseEximLogLine(line, cfg)
	if len(third) != 1 {
		t.Fatalf("expected critical finding at critical threshold, got %d: %v", len(third), third)
	}
	if third[0].Check != "email_rate_critical" {
		t.Fatalf("check = %q, want email_rate_critical", third[0].Check)
	}
}
