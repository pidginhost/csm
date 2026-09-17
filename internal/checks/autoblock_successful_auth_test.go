package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/attackdb"
	"github.com/pidginhost/csm/internal/store"
)

// A customer uploaded a file in cPanel File Manager and was firewall-blocked
// one second later:
//
//	16:21:33  cpanel_file_upload_realtime  POST /execute/Fileman/upload_files
//	16:21:34  auto_block                   AUTO-BLOCK: <ip> blocked (expires in 24h0m0s)
//
// Five more addresses were blocked for logging in to FTP successfully --
// pure-ftpd had already written "is now logged in" for each.
//
// These checks fire on operations that SUCCEEDED, after authentication. The
// producing handler even skips 401 and 403 so it only reports authenticated
// writes. On shared hosting every customer is a "non-infra IP", so the signal
// fires on ordinary use of core cPanel features -- uploading, saving,
// renaming, deleting, or simply logging in.
//
// The reasoning is already recorded in this file for cpanel_login:
// "a single event is not brute-force evidence. Blocking on one Warning turns
// a legitimate customer logging in from a new country into a 24h lockout."
// The same is true here; these three were missed.
//
// They stay as findings. During a live compromise "File Manager write from an
// address never seen before, on an account whose password just changed" is
// worth correlating. It is not a verdict on its own.
func TestSuccessfulAuthOperationsAreNeverBlockable(t *testing.T) {
	successAfterAuth := []string{
		"cpanel_file_upload_realtime",
		"ftp_login",
		"webmail_login_realtime",
	}
	for _, check := range successAfterAuth {
		for _, blockCpanelLogins := range []bool{false, true} {
			if blockableCheck(check, blockCpanelLogins) {
				t.Errorf("%s is block-eligible with block_cpanel_logins=%v; a successful authenticated operation must not trigger a firewall block",
					check, blockCpanelLogins)
			}
		}
	}
}

// The switch still has to do its job: failure and threshold checks are real
// evidence and must keep blocking when the operator turns it on. Removing
// those would trade one outage for another.
func TestFailureChecksStayBlockableWhenEnabled(t *testing.T) {
	failureEvidence := []string{
		"cpanel_multi_ip_login",
		"api_auth_failure",
		"api_auth_failure_realtime",
		"webmail_bruteforce",
		"ftp_auth_failure_realtime",
	}
	for _, check := range failureEvidence {
		if !blockableCheck(check, true) {
			t.Errorf("%s is not blockable with block_cpanel_logins=true; the switch no longer protects cPanel and webmail", check)
		}
		if blockableCheck(check, false) {
			t.Errorf("%s blocks with block_cpanel_logins=false; the switch is not being honoured", check)
		}
	}
}

// Checks that carry a confirmed attacker IP block regardless of the switch.
func TestAlwaysBlockableChecksIgnoreTheSwitch(t *testing.T) {
	for _, check := range []string{
		"wp_login_bruteforce", "xmlrpc_abuse", "http_request_flood", "http_scanner_profile",
		"http_claimed_bot_unverified", "http_ua_spoof", "ftp_bruteforce", "smtp_bruteforce",
		"smtp_probe_abuse", "mail_bruteforce", "mail_account_compromised", "admin_panel_bruteforce",
		"ssh_login_unknown_ip", "pam_bruteforce", "credential_stuffing",
		"c2_connection", "ip_reputation", "local_threat_score", "modsec_block_escalation",
		"modsec_csm_block_escalation", "email_compromised_account", "email_cloud_relay_abuse", "waf_attack_blocked",
	} {
		for _, blockCpanelLogins := range []bool{false, true} {
			if !blockableCheck(check, blockCpanelLogins) {
				t.Errorf("%s stopped being blockable (block_cpanel_logins=%v)", check, blockCpanelLogins)
			}
		}
	}
}

// An unknown check must not become blockable by accident.
func TestUnknownCheckIsNotBlockable(t *testing.T) {
	if blockableCheck("something_new_and_unclassified", true) {
		t.Error("an unregistered check was treated as block-eligible")
	}
}

// Exercise the whole disposition pipeline, including derived scoring and
// permanent-block promotion. A type-membership assertion alone misses both.
func TestSuccessfulAuthCannotPromoteAddressToBlock(t *testing.T) {
	withTestThreatStore(t)
	t.Cleanup(SetGlobalThreatDBForTest(t.TempDir()))
	previousDB := attackdb.Global()
	t.Cleanup(func() { attackdb.SetGlobal(previousDB) })
	oldBlocker, oldList := getIPBlocker(), GetChallengeIPList()
	t.Cleanup(func() { SetIPBlocker(oldBlocker); SetChallengeIPList(oldList) })
	for _, challengeEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("challenge=%v", challengeEnabled), func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.BlockCpanelLogins = true
			cfg.AutoResponse.PermBlock = true
			cfg.Challenge.Enabled = challengeEnabled
			blocker := &recordingIPBlocker{}
			SetIPBlocker(blocker)
			list := &staticChallengeIPList{ips: make(map[string]bool)}
			SetChallengeIPList(list)
			db := attackdb.NewForTest(nil)
			attackdb.SetGlobal(db)
			const ip = "198.51.100.90"
			// This one C2-class finding scores 37, below the local block
			// threshold. Audit traffic must not raise it to 75.
			db.RecordFinding(alert.Finding{Check: "suspicious_process", SourceIP: ip, TenantID: "alice"})
			for range 3 {
				var findings []alert.Finding
				for _, check := range []string{"cpanel_file_upload_realtime", "cpanel_login", "cpanel_login_realtime", "ftp_login", "webmail_login_realtime", "pam_login"} {
					f := alert.Finding{Check: check, SourceIP: ip, TenantID: "bob", Severity: alert.Warning, Timestamp: time.Now()}
					db.RecordFinding(f)
					findings = append(findings, f)
				}
				derived := CheckLocalThreatScore(context.Background(), cfg, nil)
				if len(derived) != 0 {
					t.Errorf("successful activity generated local threat findings: %+v", derived)
				}
				findings = append(findings, derived...)
				challenges, blocks := ChallengeThenBlock(cfg, findings)
				if len(challenges) != 0 || len(blocks) != 0 || len(blocker.blocked) != 0 || list.Contains(ip) {
					t.Fatalf("audit activity reached disposition: challenges=%+v blocks=%+v calls=%v", challenges, blocks, blocker.blocked)
				}
			}
			if _, found := store.Global().GetPermanentBlock(ip); found {
				t.Fatal("audit activity created local blocklist evidence")
			}
			state := loadBlockState(cfg.StatePath)
			if len(state.IPs) != 0 || len(state.Pending) != 0 || len(loadPermBlockTracker(cfg.StatePath).IPs) != 0 {
				t.Fatalf("audit activity changed block state: %+v", state)
			}
		})
	}
}

// Old queues have no check identity; their free-text reason cannot prove
// eligibility under the current policy. Fresh qualifying evidence can requeue.
func TestPendingBlocksRecheckEligibility(t *testing.T) {
	tests := []struct {
		name, check        string
		enabled, wantBlock bool
	}{
		{name: "legacy upload"},
		{name: "removed upload", check: "cpanel_file_upload_realtime", enabled: true},
		{name: "removed FTP success", check: "ftp_login", enabled: true},
		{name: "removed webmail success", check: "webmail_login_realtime", enabled: true},
		{name: "disabled API failure", check: "api_auth_failure_realtime"},
		{name: "enabled API failure", check: "api_auth_failure_realtime", enabled: true, wantBlock: true},
		{name: "always block", check: "wp_login_bruteforce", wantBlock: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.BlockCpanelLogins = tt.enabled
			raw, err := json.Marshal(map[string]any{"pending": []map[string]any{{
				"ip": "198.51.100.91", "reason": "cPanel File Manager write from non-infra IP: 198.51.100.91",
				"check": tt.check, "severity": alert.Critical, "queued_at": time.Now(),
			}}})
			if err != nil {
				t.Fatal(err)
			}
			var state blockState
			if err := json.Unmarshal(raw, &state); err != nil {
				t.Fatal(err)
			}
			saveBlockState(cfg.StatePath, &state)
			blocker := &recordingIPBlocker{}
			old := getIPBlocker()
			SetIPBlocker(blocker)
			t.Cleanup(func() { SetIPBlocker(old) })
			AutoBlockIPs(cfg, nil)
			if got := len(blocker.blocked); got != 0 && !tt.wantBlock || got != 1 && tt.wantBlock {
				t.Fatalf("blocked %d addresses; wantBlock=%v", got, tt.wantBlock)
			}
			if got := loadBlockState(cfg.StatePath).Pending; len(got) != 0 {
				t.Fatalf("ineligible or completed candidate still pending: %+v", got)
			}
		})
	}
}

func TestCpanelFailureResponsesHonorToggle(t *testing.T) {
	oldBlocker, oldList := getIPBlocker(), GetChallengeIPList()
	t.Cleanup(func() { SetIPBlocker(oldBlocker); SetChallengeIPList(oldList) })
	for _, check := range []string{"cpanel_multi_ip_login", "api_auth_failure", "api_auth_failure_realtime", "webmail_bruteforce", "ftp_auth_failure_realtime"} {
		for _, enabled := range []bool{false, true} {
			for _, challengeEnabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/block=%v/challenge=%v", check, enabled, challengeEnabled), func(t *testing.T) {
					cfg := pendingTestConfig(t)
					cfg.AutoResponse.BlockCpanelLogins = enabled
					cfg.Challenge.Enabled = challengeEnabled
					SetIPBlocker(&recordingIPBlocker{})
					SetChallengeIPList(&staticChallengeIPList{ips: make(map[string]bool)})
					findings := []alert.Finding{{Check: check, SourceIP: "198.51.100.93", Severity: alert.Critical}}
					challenged, blocked := ChallengeThenBlock(cfg, findings)
					wantChallenges, wantBlocks := 0, 0
					if enabled {
						if challengeEnabled && check == "webmail_bruteforce" {
							wantChallenges = 1
						} else {
							wantBlocks = 1
						}
					}
					if len(challenged) != wantChallenges || len(blocked) != wantBlocks {
						t.Fatalf("actions challenge/block = %d/%d, want %d/%d", len(challenged), len(blocked), wantChallenges, wantBlocks)
					}
				})
			}
		}
	}
}

func TestQueuedBlockRetainsFindingEligibility(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.BlockCpanelLogins = true
	old := getIPBlocker()
	t.Cleanup(func() { SetIPBlocker(old) })
	SetIPBlocker(&failingIPBlocker{})
	f := alert.Finding{Check: "ftp_auth_failure_realtime", Severity: alert.High, SourceIP: "198.51.100.94"}
	AutoBlockIPs(cfg, []alert.Finding{f})
	pending := loadBlockState(cfg.StatePath).Pending
	if len(pending) != 1 || pending[0].Check != f.Check || pending[0].Severity != f.Severity || pending[0].QueuedAt.IsZero() {
		t.Fatalf("retry lost finding eligibility: %+v", pending)
	}
	// A config reload after the failed attempt must take effect on retry.
	cfg.AutoResponse.BlockCpanelLogins = false
	blocker := &recordingIPBlocker{}
	SetIPBlocker(blocker)
	AutoBlockIPs(cfg, nil)
	if len(blocker.blocked) != 0 || len(loadBlockState(cfg.StatePath).Pending) != 0 {
		t.Fatal("retry ignored the disabled login-blocking policy")
	}
}
