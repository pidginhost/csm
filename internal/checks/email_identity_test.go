package checks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// identityCase builds two findings through a real producer. A re-report
// differs from the first only in volatile text and must keep its email
// identity; a distinct case names another condition and must not share it.
// For a sourceNoise case the volatile part is in the producer's input, which
// its own text leaves out.
type identityCase struct {
	name        string
	build       func(t *testing.T) (alert.Finding, alert.Finding)
	distinct    bool
	sourceNoise bool
}

// Alert email and the webhook send a finding again only when Key or
// Fingerprint changes. A count, PID or error text in either would email the
// same ongoing condition on every report.
func TestReReportKeepsEmailIdentity(t *testing.T) {
	cases := []identityCase{
		{name: "sensitive_file_modified write", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			disableSensitiveProvenanceForTest(t)
			return sensitiveWrite(t, "/etc/passwd", 0, 4242, "useradd", nil), sensitiveWrite(t, "/etc/passwd", 0, 5353, "vipw", nil)
		}},
		{name: "sensitive_file_modified write same content", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			disableSensitiveProvenanceForTest(t)
			content := []byte("alice:x:1001:1001::/home/alice:/bin/bash\n")
			return sensitiveWrite(t, "/etc/passwd", 0, 4242, "useradd", content), sensitiveWrite(t, "/etc/passwd", 0, 5353, "vipw", content)
		}},
		{name: "sensitive_file_modified another content", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			disableSensitiveProvenanceForTest(t)
			return sensitiveWrite(t, "/etc/passwd", 0, 4242, "useradd", []byte("alice:x:1001:1001::/home/alice:/bin/bash\n")),
				sensitiveWrite(t, "/etc/passwd", 0, 4242, "useradd", []byte("alice:x:0:0::/home/alice:/bin/bash\n"))
		}},
		{name: "sensitive_file_modified another path", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			disableSensitiveProvenanceForTest(t)
			return sensitiveWrite(t, "/etc/passwd", 0, 4242, "useradd", nil), sensitiveWrite(t, "/etc/shadow", 0, 4242, "useradd", nil)
		}},
		// Both writers are unprivileged, so the severity is the same.
		{name: "sensitive_file_modified another writer", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			disableSensitiveProvenanceForTest(t)
			return sensitiveWrite(t, "/etc/passwd", 1000, 4242, "useradd", nil), sensitiveWrite(t, "/etc/passwd", 1001, 4242, "useradd", nil)
		}},
		// A demoted write must not hide a later full-severity write to the
		// same file while the first is still remembered.
		{name: "sensitive_file_modified demoted then undemoted", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			disableSensitiveProvenanceForTest(t)
			AncestryProvenance = func(pid uint32) string {
				if pid == 4242 {
					return "writer descends from the panel updater"
				}
				return ""
			}
			demoted, full := sensitiveWrite(t, "/etc/passwd", 0, 4242, "useradd", nil), sensitiveWrite(t, "/etc/passwd", 0, 5353, "useradd", nil)
			if demoted.Severity != alert.Warning || full.Severity != alert.High {
				t.Fatalf("severities = %v, %v; want WARNING then HIGH", demoted.Severity, full.Severity)
			}
			return demoted, full
		}},
		// The affected accounts are the condition: more evidence in the same
		// accounts is not news, spread to another account is.
		{name: "coordinated_attack same accounts", sourceNoise: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			more := append(criticalWebshells("webshell", "carol", "bob", "alice"), criticalWebshells("backdoor_binary", "alice")...)
			return derivedFinding(t, "coordinated_attack", criticalWebshells("webshell", "alice", "bob", "carol")),
				derivedFinding(t, "coordinated_attack", more)
		}},
		{name: "coordinated_attack spread", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return derivedFinding(t, "coordinated_attack", criticalWebshells("webshell", "alice", "bob", "carol")),
				derivedFinding(t, "coordinated_attack", criticalWebshells("webshell", "alice", "bob", "carol", "dave"))
		}},
		{name: "cross_account_malware same accounts", sourceNoise: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			more := criticalWebshells("webshell", "bob", "alice", "alice")
			more[2].FilePath, more[2].Message = "/home/alice/public_html/y.php", "malware in /home/alice/public_html/y.php"
			return derivedFinding(t, "cross_account_malware", criticalWebshells("webshell", "alice", "bob")),
				derivedFinding(t, "cross_account_malware", more)
		}},
		{name: "cross_account_malware spread", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return derivedFinding(t, "cross_account_malware", criticalWebshells("webshell", "alice", "bob")),
				derivedFinding(t, "cross_account_malware", criticalWebshells("webshell", "alice", "bob", "carol"))
		}},
		{name: "cross_account_malware another malware check", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return derivedFinding(t, "cross_account_malware", criticalWebshells("webshell", "alice", "bob")),
				derivedFinding(t, "cross_account_malware", criticalWebshells("backdoor_binary", "alice", "bob"))
		}},
		{name: "auto_block accounting", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return scanAccountingNotice(t, "budget storage unavailable"), scanAccountingNotice(t, "budget bucket locked")
		}},
		{name: "auto_block spray accounting", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return sprayAccountingNotice(t, "state file read-only"), sprayAccountingNotice(t, "no space left on device")
		}},
		{name: "auto_block rate limit", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return rateLimitNotice(t, 1), rateLimitNotice(t, 2)
		}},
		{name: "auto_block pending dropped", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return pendingDroppedNotice(t, 1), pendingDroppedNotice(t, 2)
		}},
		{name: "auto_block rate limit and pending dropped", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return rateLimitNotice(t, 1), pendingDroppedNotice(t, 1)
		}},
		{name: "auto_block rate limit with drops", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return sprayBudgetNotice(t, maxPendingBlocks/2+1), sprayBudgetNotice(t, maxPendingBlocks/2+2)
		}},
		// IPs dropped from the queue are never blocked. Drops starting during
		// a rate limit already reported are news.
		{name: "auto_block rate limit without and with drops", distinct: true, build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return sprayBudgetNotice(t, 1), sprayBudgetNotice(t, maxPendingBlocks/2+1)
		}},

		// Already stable: pins only.
		{name: "admin_cross_account_overlap", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			overlap := func(seen time.Time) alert.Finding {
				return onlyFinding(t, buildAdminOverlapFindings(map[string][]store.AdminEmailEntry{
					"owner@example.com": {{Account: "alice", Schema: "alice_wp", LastSeen: seen}, {Account: "bob", Schema: "bob_wp", LastSeen: seen}},
				}))
			}
			at := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
			return overlap(at), overlap(at.Add(time.Hour))
		}},
		{name: "wp_core_unverified", build: wpUnverifiedReReport("core")},
		{name: "wp_plugin_inventory_unverified", build: wpUnverifiedReReport("plugins")},
		{name: "php_taint_scan_incomplete", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			return onlyFinding(t, phpTaintGapFindingsFor(3, 0)), onlyFinding(t, phpTaintGapFindingsFor(1, 0))
		}},
		{name: "js_taint_scan_incomplete", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			gap := func(n int) alert.Finding {
				g := newJSTaintGapCollector()
				for i := range n {
					g.record(fmt.Sprintf("/home/alice/public_html/app-%d.js", i), "parse_error")
				}
				return g.finding()
			}
			return gap(3), gap(1)
		}},
		{name: "yara_scan_incomplete", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			gap := func(n int) alert.Finding {
				g := newYARAGapCollector()
				for i := range n {
					g.record(fmt.Sprintf("/home/alice/public_html/file-%d.php", i), "read_error")
				}
				return g.finding()
			}
			return gap(3), gap(1)
		}},
		{name: "db_content_scan_incomplete", build: func(t *testing.T) (alert.Finding, alert.Finding) {
			gap := func(skipped int) alert.Finding {
				ctx, _ := withIncompleteCheckCollector(context.Background())
				markCheckIncomplete(ctx, "db_content")
				coverage := &dbScanCoverage{discovered: 40}
				for i := range skipped {
					coverage.record("query_failed", fmt.Sprintf("/home/alice%d/public_html/wp-config.php", i))
				}
				return onlyFinding(t, appendDatabaseScanIncompleteFinding(ctx, nil, coverage))
			}
			return gap(4), gap(1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, second := tc.build(t)
			if first.Check == "" || first.Check != second.Check {
				t.Fatalf("fixture built %q and %q, want one check", first.Check, second.Check)
			}
			if tc.distinct {
				if first.Key() == second.Key() {
					t.Fatalf("distinct conditions share identity %q:\n first=%+v\nsecond=%+v", first.Key(), first, second)
				}
				return
			}
			if !tc.sourceNoise && first.Message == second.Message && first.Details == second.Details {
				t.Fatalf("fixture does not vary between reports: %+v", first)
			}
			if first.Key() != second.Key() {
				t.Fatalf("identity changed between reports:\n first=%q\nsecond=%q", first.Key(), second.Key())
			}
			if first.Fingerprint() != second.Fingerprint() {
				t.Fatalf("fingerprint changed between reports: %q vs %q", first.Fingerprint(), second.Fingerprint())
			}
		})
	}
}

func onlyFinding(t *testing.T, findings []alert.Finding) alert.Finding {
	t.Helper()
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", findings)
	}
	return findings[0]
}

// sensitiveWrite evaluates a live write; nil content means it was unreadable.
func sensitiveWrite(t *testing.T, path string, uid, pid uint32, comm string, content []byte) alert.Finding {
	t.Helper()
	f, ok := EvaluateSensitiveFileWriteSnapshot(path, uid, pid, comm, content, content != nil)
	if !ok {
		t.Fatalf("no finding for a write to %s", path)
	}
	return f
}

func criticalWebshells(check string, accounts ...string) []alert.Finding {
	out := make([]alert.Finding, 0, len(accounts))
	for _, account := range accounts {
		out = append(out, alert.Finding{
			Check: check, Severity: alert.Critical, TenantID: account,
			FilePath: "/home/" + account + "/public_html/x.php", Message: "malware in /home/" + account + "/public_html/x.php",
		})
	}
	return out
}

func derivedFinding(t *testing.T, check string, sources []alert.Finding) alert.Finding {
	t.Helper()
	var out []alert.Finding
	for _, f := range CorrelateBatchFindings(sources).Derived {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return onlyFinding(t, out)
}

func autoBlockNotice(t *testing.T, actions []alert.Finding, prefix string) alert.Finding {
	t.Helper()
	var out []alert.Finding
	for _, f := range actions {
		if f.Check == "auto_block" && f.Severity == alert.Warning && strings.HasPrefix(f.Message, prefix) {
			out = append(out, f)
		}
	}
	return onlyFinding(t, out)
}

func scanAccountingNotice(t *testing.T, cause string) alert.Finding {
	t.Helper()
	cfg := pendingTestConfig(t)
	applyBlockTestSetup(t, &scanAdmissionBlocker{readErr: errors.New(cause)})
	actions := AutoBlockIPs(cfg, []alert.Finding{wafFinding("192.0.2.71")})
	return autoBlockNotice(t, actions, "Firewall action accounting unavailable")
}

func sprayAccountingNotice(t *testing.T, cause string) alert.Finding {
	t.Helper()
	cfg := pendingTestConfig(t)
	applyBlockTestSetup(t, &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive})
	previous := persistAutoBlockState
	t.Cleanup(func() { persistAutoBlockState = previous })
	persistAutoBlockState = func(path string, state *blockState) error {
		if state.LoginSprayBlocksThisHour > 0 {
			return errors.New(cause)
		}
		return writeBlockState(path, state)
	}
	var actions []alert.Finding
	captureStderr(t, func() { actions = AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.72")}) })
	return autoBlockNotice(t, actions, "Block accounting unavailable")
}

func rateLimitNotice(t *testing.T, queued int) alert.Finding {
	t.Helper()
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1
	now := time.Now()
	setAutoBlockNow(t, now)
	saveBlockState(cfg.StatePath, &blockState{HourKey: now.Format("2006-01-02T15"), BlocksThisHour: 1})
	applyBlockTestSetup(t, &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive})
	var findings []alert.Finding
	for i := range queued {
		findings = append(findings, wafFinding(fmt.Sprintf("198.51.100.%d", 80+i)))
	}
	return autoBlockNotice(t, AutoBlockIPs(cfg, findings), "Auto-block rate limit reached")
}

// sprayBudgetNotice queues spray findings while the spray budget is spent.
// More than half the queue overflows the spray share.
func sprayBudgetNotice(t *testing.T, spray int) alert.Finding {
	t.Helper()
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1
	now := time.Now()
	setAutoBlockNow(t, now)
	saveBlockState(cfg.StatePath, &blockState{HourKey: now.Format("2006-01-02T15"), LoginSprayBlocksThisHour: 1})
	applyBlockTestSetup(t, &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive})
	var findings []alert.Finding
	for i := range spray {
		findings = append(findings, loginSprayFinding(fmt.Sprintf("2001:db8:8::%x", i)))
	}
	var actions []alert.Finding
	captureStderr(t, func() { actions = AutoBlockIPs(cfg, findings) })
	return autoBlockNotice(t, actions, "Auto-block mail login spray budget reached")
}

// pendingDroppedNotice overflows the spray share of the retry queue while
// the firewall engine is unavailable, so no rate limit is involved.
func pendingDroppedNotice(t *testing.T, dropped int) alert.Finding {
	t.Helper()
	cfg := pendingTestConfig(t)
	setAutoBlockNow(t, time.Now())
	previous := getIPBlocker()
	SetIPBlocker(nil)
	t.Cleanup(func() { SetIPBlocker(previous) })
	saveBlockState(cfg.StatePath, &blockState{})
	var findings []alert.Finding
	for i := range maxPendingBlocks/2 + dropped {
		findings = append(findings, loginSprayFinding(fmt.Sprintf("2001:db8:7::%x", i)))
	}
	var actions []alert.Finding
	captureStderr(t, func() { actions = AutoBlockIPs(cfg, findings) })
	return autoBlockNotice(t, actions, "Auto-block mail spray share of the queue full")
}

func wpUnverifiedReReport(kind string) func(t *testing.T) (alert.Finding, alert.Finding) {
	return func(t *testing.T) (alert.Finding, alert.Finding) {
		db := setupPluginStore(t)
		paths := map[string]string{"/home/alice/site": "alice"}
		results := map[string]store.WPVerificationResult{"/home/alice/site": {State: "unverified", Reason: "wp-cli timed out"}}
		at := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
		var reports []alert.Finding
		for cycle := range 3 {
			if err := db.UpdateWPVerification(kind, at.Add(time.Duration(cycle)*time.Hour), "", paths, results, true); err != nil {
				t.Fatal(err)
			}
			if cycle > 0 {
				reports = append(reports, onlyFinding(t, wpVerificationFindings(context.Background(), db, kind, "", nil)))
			}
		}
		return reports[0], reports[1]
	}
}
