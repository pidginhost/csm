package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/geoip"
	"github.com/pidginhost/csm/internal/store"
)

// withOwnerTable maps example.com to alice and example.net to bob, and
// recognises alice and bob as hosting accounts; every other domain and user
// is unmapped, so a finding for it must stay unattributed.
func withOwnerTable(t *testing.T) {
	t.Helper()
	t.Cleanup(checks.SetAccountOwnerLookupForTest(func(domain string) (string, bool) {
		switch domain {
		case "example.com":
			return "alice", true
		case "example.net":
			return "bob", true
		}
		return "", false
	}))
	t.Cleanup(checks.SetHostingAccountLookupForTest(func(name string) string {
		switch name {
		case "alice", "bob":
			return name
		}
		return ""
	}))
}

// requireOwner finds the first finding of check, asserts its TenantID and,
// for an attributed row, proves correlation counts it: a Critical completes
// a three-account aggregate with two anchors and nothing is unattributed.
func requireOwner(t *testing.T, findings []alert.Finding, check, owner string) alert.Finding {
	t.Helper()
	for _, f := range findings {
		if f.Check != check {
			continue
		}
		if f.TenantID != owner {
			t.Fatalf("%s: TenantID %q, want %q (%+v)", check, f.TenantID, owner, f)
		}
		if f.TenantID != "" {
			res := checks.CorrelateFindings([]alert.Finding{f, {Severity: alert.Critical, Check: "db_rogue_admin", TenantID: "carol"}, {Severity: alert.Critical, Check: "db_rogue_admin", TenantID: "dave"}})
			if f.Severity == alert.Critical && len(res.Derived) != 1 {
				t.Fatalf("%s: attributed Critical did not complete a three-account aggregate: %+v", check, res)
			}
			if len(res.Unattributed) != 0 {
				t.Fatalf("%s: attributed finding counted as unattributed: %v", check, res.Unattributed)
			}
		}
		return f
	}
	t.Fatalf("no %s finding in %+v", check, findings)
	return alert.Finding{}
}

func TestWatcherMailFindingsStampOwner(t *testing.T) {
	withOwnerTable(t)
	resetEmailRateState()
	t.Cleanup(resetEmailRateState)
	cfg := &config.Config{}
	// The mail-hold path dedups through the global store.
	withGlobalStore(t, func(*store.DB) {
		hold := `2026-09-08 10:00:00 Sender user@example.com has an outgoing mail hold`
		requireOwner(t, parseEximLogLine(hold, cfg), "email_compromised_account", "alice")
		unmapped := `2026-09-08 10:00:03 Sender user@example.org has an outgoing mail hold`
		requireOwner(t, parseEximLogLine(unmapped, cfg), "email_compromised_account", "")
	})

	leak := `2026-09-08 10:00:01 1abc23-000456-AB <= user@example.net H=mail.example.net [203.0.113.42] P=esmtpsa A=dovecot_login:user@example.net S=1234 T="smtp.example.org:587,user@example.net,secret"`
	requireOwner(t, parseEximLogLine(leak, cfg), "email_credential_leak", "bob")

	bulk := `2026-09-08 10:00:02 1abc23-000457-AB <= user@example.com H=relay.truelist.io [203.0.113.43] P=esmtpsa A=dovecot_login:user@example.com S=1234 T="hello"`
	requireOwner(t, parseEximLogLine(bulk, cfg), "email_compromised_account", "alice")

	// The governor line escalates to an outbreak only with a corroborating
	// outbound blast from the domain's own senders.
	resetEmailRateState()
	rate := testEmailProtectionConfig()
	for i := 0; i < rate.EmailProtection.RateCritThreshold; i++ {
		_ = checkEmailRate("sales@example.net", rate)
	}
	governor := `2026-09-08 10:00:04 Domain example.net has exceeded the max defers and failures per hour (5/5 (100%)) allowed. Message discarded.`
	requireOwner(t, parseEximLogLine(governor, rate), "email_spam_outbreak", "bob")
}

func TestWatcherEmailRateStampsOwner(t *testing.T) {
	withOwnerTable(t)
	resetEmailRateState()
	t.Cleanup(resetEmailRateState)
	cfg := testEmailProtectionConfig()
	var findings []alert.Finding
	for i := 0; i < 3; i++ {
		findings = append(findings, checkEmailRate("user@example.com", cfg)...)
	}
	requireOwner(t, findings, "email_rate_warning", "alice")
	requireOwner(t, findings, "email_rate_critical", "alice")

	resetEmailRateState()
	var bare []alert.Finding
	for i := 0; i < 3; i++ {
		bare = append(bare, checkEmailRate("bob", cfg)...)
	}
	// The local resolver confirms this bare account name as a hosting owner.
	requireOwner(t, bare, "email_rate_critical", "bob")

	resetEmailRateState()
	var unmapped []alert.Finding
	for i := 0; i < 3; i++ {
		unmapped = append(unmapped, checkEmailRate("user@example.org", cfg)...)
	}
	requireOwner(t, unmapped, "email_rate_critical", "")
}

func TestMailBruteCompromiseStampsOwner(t *testing.T) {
	withOwnerTable(t)
	clock := &staticClock{t: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)}
	tr := newTestMailTracker(t, clock)
	for i := 0; i < 3; i++ {
		tr.Record("203.0.113.5", "user@example.com")
	}
	requireOwner(t, tr.RecordSuccess("203.0.113.5", "user@example.com"), "mail_account_compromised", "alice")
	for i := 0; i < 3; i++ {
		tr.Record("203.0.113.6", "user@example.org")
	}
	requireOwner(t, tr.RecordSuccess("203.0.113.6", "user@example.org"), "mail_account_compromised", "")
}

func TestPHPRelayAbuseStampsOwner(t *testing.T) {
	withOwnerTable(t)
	now := time.Now()
	eng := newEvaluator(newPerScriptWindow(), newPerIPWindow(64), nil, defaultPHPRelayCfg(), nil)
	f := eng.makeFinding("example.test:/mail.php", "path1", "203.0.113.7", "alice", &scriptState{}, "fixture", now)
	if f.TenantID != "alice" || f.CPUser != "alice" {
		t.Fatalf("script path finding: %+v", f)
	}
	rootOwned := eng.makeFinding("example.test:/mail.php", "path1", "203.0.113.7", "root", &scriptState{}, "fixture", now)
	if rootOwned.TenantID != "" {
		t.Fatalf("root spool user stamped as a hosting owner: %+v", rootOwned)
	}

	startup := defaultPHPRelayCfg()
	startup.EmailProtection.PHPRelay.AccountVolumePerHour = 2
	accounts := newPerAccountWindow(5000)
	volume := newEvaluator(nil, nil, accounts, startup, nil)
	volume.SetEffectiveAccountLimit(2)
	line := "2026-09-08 12:00:00 1abcdefghijk-DEF <= info@example.com U=bob ID=1 B=redirect_resolver"
	_ = volume.parsePHPRelayAccountVolumeAt(line, now, now)
	got := volume.parsePHPRelayAccountVolumeAt(line, now, now)
	requireOwner(t, got, "email_php_relay_abuse", "bob")
	system := "2026-09-08 12:00:00 1abcdefghijk-DEG <= info@example.com U=mailnull ID=2 B=redirect_resolver"
	_ = volume.parsePHPRelayAccountVolumeAt(system, now, now)
	requireOwner(t, volume.parsePHPRelayAccountVolumeAt(system, now, now), "email_php_relay_abuse", "")
}

func TestPHPShieldFindingsStampOwner(t *testing.T) {
	for _, tc := range []struct{ line, check string }{
		{`[2026-04-12 10:00:00] BLOCK_PATH ip=203.0.113.5 script=/home/alice/public_html/evil.php details=blocked dangerous path`, "php_shield_block"},
		{`[2026-04-12 10:00:01] WEBSHELL_PARAM ip=203.0.113.5 script=/home/alice/public_html/x.php uri=/x.php?cmd=id ua=curl`, "php_shield_webshell"},
		{`[2026-04-12 10:00:02] BLOCK_WEBSHELL ip=203.0.113.5 script=/home/alice/public_html/y.php details=signature`, "php_shield_webshell"},
		{`[2026-04-12 10:00:03] EVAL_FATAL ip=203.0.113.5 script=/home/alice/public_html/z.php details=eval chain`, "php_shield_eval"},
	} {
		f := parsePHPShieldLine(tc.line)
		if f == nil || f.Check != tc.check {
			t.Fatalf("%s: finding %+v", tc.check, f)
		}
		if f.FilePath == "" || f.FilePath != scriptOf(tc.line) {
			t.Fatalf("%s: FilePath %q, want the script path", tc.check, f.FilePath)
		}
	}
}

func scriptOf(line string) string {
	for _, kv := range splitKV(line[len("[2026-04-12 10:00:00] XXXX "):]) {
		if kv[0] == "script" {
			return kv[1]
		}
	}
	return ""
}

func TestPasswordHijackFindingsCarryTenant(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"198.51.100.1"}}
	ch := make(chan alert.Finding, 4)
	d := NewPasswordHijackDetector(cfg, ch, make(chan struct{}))
	d.HandlePasswordChange("alice", "203.0.113.5")
	d.HandleLogin("alice", "203.0.113.6")
	got := []alert.Finding{<-ch, <-ch}
	requireOwner(t, got, "whm_password_change_noninfra", "alice")
	requireOwner(t, got, "password_hijack_confirmed", "alice")
}

func TestCloudRelayFindingCarriesTenant(t *testing.T) {
	withOwnerTable(t)
	resetCloudRelayState()
	resetEmailRateState()
	t.Cleanup(resetEmailRateState)
	cfg := cloudRelayTestConfig()
	live := func(sender string) []alert.Finding {
		var out []alert.Finding
		for _, ip := range []string{"203.0.113.11", "203.0.113.12", "203.0.113.13"} {
			out = append(out, parseEximLogLine(gceSendLine(sender, strings.ReplaceAll(ip, ".", "-")+".bc.googleusercontent.com", ip), cfg)...)
		}
		return out
	}
	requireOwner(t, live("info@example.com"), "email_cloud_relay_abuse", "alice")
	requireOwner(t, live("info@example.org"), "email_cloud_relay_abuse", "")
	requireOwner(t, live("bob"), "email_cloud_relay_abuse", "bob")
	requireOwner(t, live("nobody"), "email_cloud_relay_abuse", "")

	// The retrospective log replay stamps the same owner.
	base := time.Now().Add(-2 * time.Hour)
	var lines []string
	for i := 0; i < 18; i++ {
		lines = append(lines, eximLine(base.Add(time.Duration(i)*2*time.Minute), "sales@example.net",
			"ec2-192-0-2-10.eu-west-3.compute.amazonaws.com", "192.0.2.10", "fixture"))
	}
	path := writeEximFixture(t, lines)
	withGlobalStore(t, func(*store.DB) {
		requireOwner(t, ScanEximHistoryForCloudRelay(&config.Config{}, path, time.Now(), 24*time.Hour), "email_cloud_relay_abuse", "bob")
	})
}

func TestDovecotGeoFindingCarriesTenant(t *testing.T) {
	withOwnerTable(t)
	prev := geoLookup
	geoLookup = func(ip string) geoip.Info {
		if strings.HasPrefix(ip, "203.0.113.") {
			return geoip.Info{IP: ip, Country: "RO", CountryName: "Romania"}
		}
		return geoip.Info{IP: ip, Country: "US", CountryName: "United States"}
	}
	t.Cleanup(func() { geoLookup = prev })
	login := func(user, ip string) string {
		return `Apr  4 10:15:23 server dovecot: imap-login: Login: user=<` + user + `>, method=PLAIN, rip=` + ip + `, lip=198.51.100.7`
	}
	withGlobalStore(t, func(*store.DB) {
		cfg := &config.Config{}
		for _, user := range []string{"user@example.com", "user@example.org", "bob", "nobody"} {
			for i := 0; i < geoMinLoginCount; i++ {
				if got := parseDovecotLogLine(login(user, "198.51.100.20"), cfg); len(got) != 0 {
					t.Fatalf("baseline login alerted: %+v", got)
				}
			}
		}
		requireOwner(t, parseDovecotLogLine(login("user@example.com", "203.0.113.9"), cfg), "email_suspicious_geo", "alice")
		requireOwner(t, parseDovecotLogLine(login("user@example.org", "203.0.113.9"), cfg), "email_suspicious_geo", "")
		requireOwner(t, parseDovecotLogLine(login("bob", "203.0.113.9"), cfg), "email_suspicious_geo", "bob")
		requireOwner(t, parseDovecotLogLine(login("nobody", "203.0.113.9"), cfg), "email_suspicious_geo", "")
	})
}

// The dropper engine emits the vanished file's own path; the production
// wiring binds that emit to sendAlertWithPath, which carries it as FilePath.
func TestDropperEngineFindingAttributesByPath(t *testing.T) {
	now := time.Unix(1_770_000_000, 0)
	e, got := newTestEngine(3 * time.Minute)
	dropped := "/home/alice/public_html/wp-content/plugins/x/x.php"
	admitPHP(e, now, dropped)
	prober := &fakeProber{}
	e.probeStep(now.Add(4*time.Minute), prober, now.Add(4*time.Minute))
	e.probeStep(now.Add(4*time.Minute+dropperGraceWindow+time.Second), prober, now.Add(4*time.Minute+dropperGraceWindow+time.Second))
	if len(*got) != 1 {
		t.Fatalf("emitted %d findings, want 1", len(*got))
	}
	a := (*got)[0]
	if a.check != dropperCheckName || a.path != dropped {
		t.Fatalf("alert = %+v, want %s at %s", a, dropperCheckName, dropped)
	}
	f := alert.Finding{Severity: a.sev, Check: a.check, Message: a.msg, Details: a.details, FilePath: a.path}
	requireOwner(t, []alert.Finding{f}, dropperCheckName, "")
	res := checks.CorrelateFindings([]alert.Finding{f, {Severity: alert.Critical, Check: "db_rogue_admin", TenantID: "carol"}, {Severity: alert.Critical, Check: "db_rogue_admin", TenantID: "dave"}})
	if len(res.Derived) != 1 || len(res.Unattributed) != 0 {
		t.Fatalf("path-attributed dropper finding did not aggregate: %+v", res)
	}
}

func TestMailFindingsUseAuthenticatedOwner(t *testing.T) {
	withOwnerTable(t)
	resetEmailRateState()
	t.Cleanup(resetEmailRateState)
	for _, tc := range []struct{ name, auth, owner string }{
		{"different sender", " A=dovecot_login:user@example.net", "bob"},
		{"bare hosting user", " A=dovecot_login:bob", "bob"},
		{"service user", " A=dovecot_login:nobody", ""},
		{"unmapped mailbox", " A=dovecot_login:user@example.org", ""},
		{"unauthenticated sender", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := `2026-09-08 10:00:00 1abc23-000456-AB <= user@example.com H=mail.example.org [203.0.113.42] P=esmtpsa` + tc.auth + ` S=100 T="smtp password fixture"`
			requireOwner(t, parseEximLogLine(line, &config.Config{}), "email_credential_leak", tc.owner)
			if tc.auth != "" {
				line = strings.Replace(line, "mail.example.org", "relay.truelist.io", 1)
				requireOwner(t, parseEximLogLine(line, &config.Config{}), "email_compromised_account", tc.owner)
			}
		})
	}
	spoof := `2026-09-08 10:00:00 1abc23-000456-AB <= user@example.com H=(A=dovecot_login:user@example.net) [203.0.113.42] P=esmtp S=100 T="smtp password fixture A=dovecot_login:user@example.net"`
	requireOwner(t, parseEximLogLine(spoof, &config.Config{}), "email_credential_leak", "")
}

func TestMailOwnerLookupsRunAfterTrackerUnlock(t *testing.T) {
	resetEmailRateState()
	t.Cleanup(resetEmailRateState)
	cfg := testEmailProtectionConfig()
	tr := newTestMailTracker(t, &staticClock{t: time.Now()})
	account := "user@example.com"
	for i := 0; i < 3; i++ {
		tr.Record("203.0.113.5", account)
	}
	t.Cleanup(checks.SetAccountOwnerLookupForTest(func(domain string) (string, bool) {
		if !tr.mu.TryLock() {
			t.Error("mail tracker locked during owner lookup")
		} else {
			tr.mu.Unlock()
		}
		if val, ok := emailRateWindows.Load(account); ok {
			rw := val.(*rateWindow)
			if !rw.mu.TryLock() {
				t.Error("rate window locked during owner lookup")
			} else {
				rw.mu.Unlock()
			}
		}
		return "alice", true
	}))
	requireOwner(t, tr.RecordSuccess("203.0.113.5", account), "mail_account_compromised", "alice")
	var findings []alert.Finding
	for i := 0; i < 3; i++ {
		findings = append(findings, checkEmailRate(account, cfg)...)
	}
	requireOwner(t, findings, "email_rate_critical", "alice")
}

func TestMailBruteResolvesBareHostingOwner(t *testing.T) {
	withOwnerTable(t)
	for _, tc := range []struct{ account, owner string }{{"alice", "alice"}, {"nobody", ""}} {
		tr := newTestMailTracker(t, &staticClock{t: time.Now()})
		for i := 0; i < 3; i++ {
			tr.Record("203.0.113.5", tc.account)
		}
		requireOwner(t, tr.RecordSuccess("203.0.113.5", tc.account), "mail_account_compromised", tc.owner)
	}
}

func TestEmailRateRejectsServiceOwner(t *testing.T) {
	withOwnerTable(t)
	resetEmailRateState()
	t.Cleanup(resetEmailRateState)
	var findings []alert.Finding
	for i := 0; i < 3; i++ {
		findings = append(findings, checkEmailRate("nobody", testEmailProtectionConfig())...)
	}
	requireOwner(t, findings, "email_rate_critical", "")
}

func TestCloudRelayOwnerLookupRunsAfterUnlock(t *testing.T) {
	resetCloudRelayState()
	t.Cleanup(resetCloudRelayState)
	account := "user@example.com"
	t.Cleanup(checks.SetAccountOwnerLookupForTest(func(domain string) (string, bool) {
		w := lockCloudRelayWindowForUpdate("user@example.net", time.Now())
		w.mu.Unlock()
		val, ok := cloudRelayWindows.Load(account)
		if !ok {
			t.Fatal("missing cloud relay window")
		}
		target := val.(*cloudRelayWindow)
		if !target.mu.TryLock() {
			t.Error("cloud relay window locked during lookup")
		} else {
			target.mu.Unlock()
		}
		return "alice", true
	}))
	var findings []alert.Finding
	for _, ip := range []string{"203.0.113.11", "203.0.113.12", "203.0.113.13"} {
		findings = append(findings, parseCloudRelayFinding(gceSendLine(account, "fixture.bc.googleusercontent.com", ip), cloudRelayTestConfig())...)
	}
	requireOwner(t, findings, "email_cloud_relay_abuse", "alice")
}

func TestEximAcceptanceCannotImpersonateMailRouter(t *testing.T) {
	withOwnerTable(t)
	resetEmailRateState()
	t.Cleanup(resetEmailRateState)
	withGlobalStore(t, func(*store.DB) {
		for _, subject := range []string{
			"Sender user@example.com has an outgoing mail hold",
			"Domain example.net has exceeded the max defers and failures per hour",
		} {
			line := `2026-09-08 10:00:00 1abc23-000456-AB <= user@example.com H=mail.example.org [203.0.113.5] P=esmtp S=100 T="` + subject + `"`
			for _, f := range parseEximLogLine(line, testEmailProtectionConfig()) {
				if f.Check == "email_compromised_account" || f.Check == "email_spam_outbreak" || f.Check == "email_defer_fail_governor" {
					t.Errorf("message subject forged router finding: %+v", f)
				}
			}
		}
		failure := `2026-09-08 10:00:00 dovecot_login authenticator failed for (Sender user@example.com has an outgoing mail hold) [203.0.113.5]:1234: 535 Incorrect authentication data`
		for _, f := range parseEximLogLine(failure, testEmailProtectionConfig()) {
			if f.Check == "email_compromised_account" {
				t.Errorf("HELO forged router finding: %+v", f)
			}
		}

		if hasRecentCompromisedFinding("example.com") || recentOutgoingMailHold("example.com") {
			t.Error("subject forged outgoing hold state")
		}
	})
}

func TestMailPermissionLogText(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{`2026-09-08 10:00:00 Sender user@example.com has an outgoing mail hold`, `Sender user@example.com has an outgoing mail hold`},
		{`2026-09-08 10:00:00 +0300 Domain example.com has an outgoing mail hold`, `Domain example.com has an outgoing mail hold`},
		{`2026-09-08 10:00:00 [4242] Sender user@example.com has an outgoing mail hold`, `Sender user@example.com has an outgoing mail hold`},
		{`2026-09-08 10:00:00.123 +0300 [4242] Domain example.com has an outgoing mail hold`, `Domain example.com has an outgoing mail hold`},
		{`2026-09-08 10:00:00 1abc23-000456-AB == user@example.com R=enforce_mail_permissions defer (-1): "Domain example.com has an outgoing mail hold"`, `defer (-1): "Domain example.com has an outgoing mail hold"`},
		{`2026-09-08 10:00:00 +0300 [4242] 1abc23-000456-AB == user@example.com R=enforce_mail_permissions defer (-1): "Domain example.com has an outgoing mail hold"`, `defer (-1): "Domain example.com has an outgoing mail hold"`},
		{`2026-09-08 10:00:00 [4242] 1abc23-000456-AB <= user@example.com T="Domain example.com has an outgoing mail hold"`, ""},
		{`2026-09-08 10:00:00 [invalid] Domain example.com has an outgoing mail hold`, ""},
		{`2026-09-08 10:00:00 [] Domain example.com has an outgoing mail hold`, ""},
		{`2026-09-08 10:00:00 [4242]`, ""},
		{`2026-09-08 10:00:00 1abc23-000456-AB ** user@example.com R=dnslookup T=remote_smtp: Domain example.com has an outgoing mail hold`, ""},
		{`2026-09-08 10:00:00 dovecot_login authenticator failed for (Domain example.com has an outgoing mail hold) [203.0.113.5]:1234: 535`, ""},
	} {
		if got := mailPermissionLogText(tc.line); got != tc.want {
			t.Errorf("mailPermissionLogText(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}
