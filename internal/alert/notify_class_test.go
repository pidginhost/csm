package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// summaryNoticeForTest stands in for checks.IsSummaryNotice, which this
// package cannot import. internal/checks runs the real registry policy
// through SplitByClass.
func summaryNoticeForTest(f Finding) bool {
	switch f.Check {
	case "auto_block":
		return f.Severity == Critical || strings.Contains(f.Message, "[dry-run]")
	case "challenge_route":
		return true
	}
	return false
}

// classIPPolicy mirrors the checks policy for the checks used here: a block
// answers attacker-side findings, a challenge answers the browser-facing
// ones, Critical reputation waits for a block, and nothing answers the WHM
// exploit indicator.
func classIPPolicy(_ *config.Config, f Finding, blocked bool) bool {
	switch f.Check {
	case "wp_login_bruteforce", "http_scanner_profile":
		return true
	case "whm_unauth_scripts_realtime":
		return false
	case "ip_reputation":
		return blocked || f.Severity != Critical
	}
	return false
}

func withSummaryNoticePolicy(t *testing.T, p func(Finding) bool) {
	t.Helper()
	previous := SetSummaryNoticePolicy(p)
	t.Cleanup(func() { SetSummaryNoticePolicy(previous) })
}

// summaryCalls records every summary hook call.
type summaryCalls struct {
	mu    sync.Mutex
	calls [][]Finding
}

func installSummaryHook(t *testing.T) *summaryCalls {
	t.Helper()
	rec := &summaryCalls{}
	SetSummaryHook(func(_ *config.Config, summary []Finding) {
		rec.mu.Lock()
		rec.calls = append(rec.calls, append([]Finding(nil), summary...))
		rec.mu.Unlock()
	})
	t.Cleanup(func() { SetSummaryHook(nil) })
	return rec
}

func (r *summaryCalls) snapshot() [][]Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]Finding(nil), r.calls...)
}

func classConfig(t *testing.T) *config.Config {
	t.Helper()
	withIPResponsePolicy(t, classIPPolicy)
	withSummaryNoticePolicy(t, summaryNoticeForTest)
	blocked, challenged := BlockedIPsFunc, ChallengedIPFunc
	BlockedIPsFunc, ChallengedIPFunc = nil, nil
	t.Cleanup(func() { BlockedIPsFunc, ChallengedIPFunc = blocked, challenged })
	return &config.Config{StatePath: t.TempDir(), Hostname: "host.example.com"}
}

func writeClassState(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func findingKeys(findings []Finding) []string {
	keys := make([]string, 0, len(findings))
	for _, f := range findings {
		keys = append(keys, f.Key())
	}
	return keys
}

func assertSplit(t *testing.T, cfg *config.Config, batch, wantImmediate, wantSummary []Finding) {
	t.Helper()
	immediate, summary := SplitByClass(cfg, batch)
	if got, want := findingKeys(immediate), findingKeys(wantImmediate); !slices.Equal(got, want) {
		t.Errorf("immediate = %v, want %v", got, want)
	}
	if got, want := findingKeys(summary), findingKeys(wantSummary); !slices.Equal(got, want) {
		t.Errorf("summary = %v, want %v", got, want)
	}
}

func TestSplitByClassHandledAttackGoesToSummary(t *testing.T) {
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	unhandled := Finding{Check: "wp_login_bruteforce", Severity: Critical, Message: "WordPress login brute force from 198.51.100.9", SourceIP: "198.51.100.9"}
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, cfg *config.Config)
		handled []Finding
	}{
		{"address in firewall state", func(t *testing.T, cfg *config.Config) {
			writeClassState(t, cfg.StatePath, "firewall/state.json", `{"blocked":[{"ip":"203.0.113.30","expires_at":"`+future+`"}]}`)
		}, []Finding{
			{Check: "wp_login_bruteforce", Severity: Critical, Message: "WordPress login brute force from 203.0.113.30", SourceIP: "203.0.113.30"},
		}},
		{"same-batch block", nil, []Finding{
			{Check: "auto_block", Severity: Critical, Message: "AUTO-BLOCK: 203.0.113.31 blocked (expires in 24h0m0s)", SourceIP: "203.0.113.31"},
			{Check: "http_scanner_profile", Severity: High, Message: "URL scanner profile from 203.0.113.31: 498 of 500 requests", SourceIP: "203.0.113.31"},
		}},
		{"same-batch netblock covers the address", nil, []Finding{
			{Check: "auto_block", Severity: Critical, Message: "AUTO-NETBLOCK: 203.0.113.0/24 blocked (5 IPs from same subnet)"},
			{Check: "wp_login_bruteforce", Severity: Critical, Message: "WordPress login brute force from 203.0.113.32", SourceIP: "203.0.113.32"},
		}},
		{"challenged browser-facing attack", func(t *testing.T, cfg *config.Config) {
			ChallengedIPFunc = func(ip string) bool { return ip == "203.0.113.33" }
		}, []Finding{
			{Check: "http_scanner_profile", Severity: High, Message: "URL scanner profile from 203.0.113.33: 498 of 500 requests", SourceIP: "203.0.113.33"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := classConfig(t)
			if tc.setup != nil {
				tc.setup(t, cfg)
			}
			batch := append([]Finding{unhandled}, tc.handled...)
			assertSplit(t, cfg, batch, []Finding{unhandled}, tc.handled)
		})
	}
}

// An attack CSM did not answer is never summary-only, whatever state or
// batch notice is nearby.
func TestSplitByClassKeepsUnhandledCritical(t *testing.T) {
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	attack := Finding{Check: "wp_login_bruteforce", Severity: Critical, Message: "WordPress login brute force from 203.0.113.20: 100 attempts", SourceIP: "203.0.113.20"}
	dryRun := Finding{Check: "auto_block", Severity: Warning, Message: "AUTO-BLOCK [dry-run]: 203.0.113.20 would be blocked (expires in 24h0m0s)", SourceIP: "203.0.113.20"}
	exploit := Finding{Check: "whm_unauth_scripts_realtime", Severity: Critical, Message: "Unauthenticated WHM script request from 203.0.113.21", SourceIP: "203.0.113.21"}
	reputation := Finding{Check: "ip_reputation", Severity: Critical, Message: "Known malicious IP accessing server: 203.0.113.22", SourceIP: "203.0.113.22"}
	route := Finding{Check: "challenge_route", Severity: Warning, Message: "CHALLENGE: 203.0.113.22 sent to PoW challenge (expires in 30m0s)"}
	for _, tc := range []struct {
		name                      string
		setup                     func(t *testing.T, cfg *config.Config)
		batch, immediate, summary []Finding
	}{
		{"no block", nil, []Finding{attack}, []Finding{attack}, nil},
		{"pending-only block row", func(t *testing.T, cfg *config.Config) {
			writeClassState(t, cfg.StatePath, "blocked_ips.json", `{"ips":[],"pending":[{"ip":"203.0.113.20"}]}`)
		}, []Finding{attack}, []Finding{attack}, nil},
		{"unverified firewall row", func(t *testing.T, cfg *config.Config) {
			writeClassState(t, cfg.StatePath, "blocked_ips.json", `{"ips":[{"ip":"203.0.113.20","expires_at":"`+future+`"}]}`)
			writeClassState(t, cfg.StatePath, "firewall/state.json", `{"blocked":[{"ip":"203.0.113.20","expires_at":"`+future+`","unverified":true}]}`)
		}, []Finding{attack}, []Finding{attack}, nil},
		{"same-batch dry-run block", nil, []Finding{dryRun, attack}, []Finding{attack}, []Finding{dryRun}},
		{"unblocked exploit marker", nil, []Finding{exploit}, []Finding{exploit}, nil},
		{"critical reputation only challenged", func(t *testing.T, cfg *config.Config) {
			ChallengedIPFunc = func(ip string) bool { return ip == "203.0.113.22" }
		}, []Finding{route, reputation}, []Finding{reputation}, []Finding{route}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := classConfig(t)
			if tc.setup != nil {
				tc.setup(t, cfg)
			}
			assertSplit(t, cfg, tc.batch, tc.immediate, tc.summary)
		})
	}
}

var (
	appliedBlockNotice = Finding{Check: "auto_block", Severity: Critical, Message: "AUTO-BLOCK: 203.0.113.40 blocked (expires in 24h0m0s)", SourceIP: "203.0.113.40"}
	classTestAlert     = Finding{Check: "test_alert", Severity: Warning, Message: "Test alert from CSM"}
)

// The summary receives the handled part of what the dispatch would
// otherwise notify: findings, or the delivery candidates that replace them,
// once by Key and muted checks included. Audit-only sources and findings
// the notification filter removed (suppression rules in the daemon) are
// evidence of a response at most, never summary entries themselves.
func TestSummaryHookSeesEligibleObservations(t *testing.T) {
	cfg := classConfig(t)
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"ops@example.com"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = "192.0.2.25:25"
	cfg.Alerts.Email.DisabledChecks = []string{"challenge_route"}
	installFakeMailer(t)
	route := Finding{Check: "challenge_route", Severity: Warning, Message: "CHALLENGE: 203.0.113.41 sent to PoW challenge (expires in 30m0s)"}
	scanner := Finding{Check: "http_scanner_profile", Severity: High, Message: "URL scanner profile from 203.0.113.41: 498 of 500 requests", SourceIP: "203.0.113.41"}
	keepAll := func(fs []Finding) []Finding { return fs }
	dropAll := func([]Finding) []Finding { return nil }

	for _, tc := range []struct {
		name     string
		dispatch func() error
		want     []Finding
	}{
		{"findings deduplicated, muted check included", func() error {
			return Dispatch(cfg, []Finding{classTestAlert, appliedBlockNotice, route, scanner, appliedBlockNotice})
		}, []Finding{appliedBlockNotice, route, scanner}},
		{"audit-only route answers a finding but is not summarized", func() error {
			return DispatchWithSources(cfg, []Finding{classTestAlert, scanner}, []Finding{route})
		}, []Finding{scanner}},
		{"no findings, candidates carry the observations", func() error {
			return DispatchWithNotificationFilter(cfg, nil, []Finding{appliedBlockNotice}, nil, []Finding{appliedBlockNotice, classTestAlert}, keepAll, nil)
		}, []Finding{appliedBlockNotice}},
		{"audit-only sources", func() error {
			return DispatchWithSources(cfg, nil, []Finding{appliedBlockNotice, classTestAlert})
		}, nil},
		{"notification filter removes everything", func() error {
			return DispatchWithNotificationFilter(cfg, []Finding{route, appliedBlockNotice}, nil, nil, nil, dropAll, nil)
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := installSummaryHook(t)
			if err := tc.dispatch(); err != nil {
				t.Fatal(err)
			}
			calls := hook.snapshot()
			if tc.want == nil {
				if len(calls) != 0 {
					t.Fatalf("summary hook saw %v, want no call", calls)
				}
				return
			}
			if len(calls) != 1 {
				t.Fatalf("summary hook calls = %d, want 1", len(calls))
			}
			if got, want := findingKeys(calls[0]), findingKeys(tc.want); !slices.Equal(got, want) {
				t.Fatalf("summary hook saw %v, want %v", got, want)
			}
		})
	}

	t.Run("no summary finding, no call", func(t *testing.T) {
		hook := installSummaryHook(t)
		if err := Dispatch(cfg, []Finding{classTestAlert}); err != nil {
			t.Fatal(err)
		}
		if calls := hook.snapshot(); len(calls) != 0 {
			t.Fatalf("summary hook called with %v for an immediate-only dispatch", calls)
		}
	})

	t.Run("no alert lock held", func(t *testing.T) {
		free := true
		SetSummaryHook(func(*config.Config, []Finding) {
			for _, mu := range []interface {
				TryLock() bool
				Unlock()
			}{&auditMu, &rateLimitMu, &summaryHookMu} {
				if !mu.TryLock() {
					free = false
					continue
				}
				mu.Unlock()
			}
		})
		t.Cleanup(func() { SetSummaryHook(nil) })
		if err := Dispatch(cfg, []Finding{appliedBlockNotice}); err != nil {
			t.Fatal(err)
		}
		if !free {
			t.Fatal("summary hook ran with an alert lock held")
		}
	})
}

// A delivery candidate is classified on its own fields. An older audit copy
// with the same Key, here a High reputation sighting a challenge answers,
// must not move the escalated Critical copy to the summary; an audit-only
// block notice still answers the attack from its address.
func TestSummaryUsesDeliverySeverityAndAuditDispositions(t *testing.T) {
	cfg := classConfig(t)
	cfg.Alerts.MaxPerHour = 10
	var hooks webhookBodies
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = hooks.server(t).URL
	summary := installSummaryHook(t)
	ChallengedIPFunc = func(ip string) bool { return ip == "203.0.113.42" }
	observed := Finding{Check: "ip_reputation", Severity: High, SourceIP: "203.0.113.42", Message: "Known malicious IP accessing server: 203.0.113.42"}
	escalated := observed
	escalated.Severity = Critical
	attack := Finding{Check: "http_scanner_profile", Severity: High, SourceIP: appliedBlockNotice.SourceIP, Message: "URL scanner profile from 203.0.113.40"}

	if err := DispatchWithNotificationFilter(cfg, nil, []Finding{observed, appliedBlockNotice}, nil, []Finding{escalated, attack}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if bodies := hooks.snapshot(); len(bodies) != 1 || !strings.Contains(bodies[0], "ip_reputation") || strings.Contains(bodies[0], "http_scanner_profile") {
		t.Errorf("webhook bodies = %q, want only the unhandled Critical reputation", bodies)
	}
	if calls := summary.snapshot(); len(calls) != 1 || !slices.Equal(findingKeys(calls[0]), findingKeys([]Finding{attack})) {
		t.Errorf("summary = %v, want only the attack the audit block notice answers", calls)
	}
}

// A panicking summary hook lost those findings: the dispatch reports it,
// and the immediate findings still go out.
func TestSummaryHookPanicIsReported(t *testing.T) {
	cfg := classConfig(t)
	cfg.Alerts.MaxPerHour = 10
	var hooks webhookBodies
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = hooks.server(t).URL
	SetSummaryHook(func(*config.Config, []Finding) { panic("summary fixture failure") })
	t.Cleanup(func() { SetSummaryHook(nil) })

	err := Dispatch(cfg, []Finding{appliedBlockNotice, classTestAlert})
	if err == nil || !strings.Contains(err.Error(), "summary: hook panicked") {
		t.Errorf("dispatch error = %v, want the summary failure", err)
	}
	if bodies := hooks.snapshot(); len(bodies) != 1 || !strings.Contains(bodies[0], "test_alert") || strings.Contains(bodies[0], "AUTO-BLOCK") {
		t.Errorf("webhook bodies = %q, want only the immediate finding", bodies)
	}
}

// CLI scans and the web UI never install a summary hook. Their dispatch
// must still succeed: the handled findings stay in audit and the data
// streams, and the immediate ones are delivered.
func TestDispatchWithoutSummaryHookSucceeds(t *testing.T) {
	cfg := classConfig(t)
	cfg.Alerts.MaxPerHour = 10
	var hooks webhookBodies
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = hooks.server(t).URL
	SetSummaryHook(nil)

	if err := Dispatch(cfg, []Finding{appliedBlockNotice, classTestAlert}); err != nil {
		t.Fatalf("dispatch without a summary hook failed: %v", err)
	}
	if bodies := hooks.snapshot(); len(bodies) != 1 || !strings.Contains(bodies[0], "test_alert") || strings.Contains(bodies[0], "AUTO-BLOCK") {
		t.Errorf("webhook bodies = %q, want only the immediate finding", bodies)
	}
}

// panelChecks records the check of every signed phpanel delivery.
type panelChecks struct {
	mu     sync.Mutex
	checks []string
}

func (p *panelChecks) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var body struct {
			Finding Finding `json:"finding"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return
		}
		p.mu.Lock()
		p.checks = append(p.checks, body.Finding.Check)
		p.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (p *panelChecks) waitFor(t *testing.T, want int) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		p.mu.Lock()
		got := append([]string(nil), p.checks...)
		p.mu.Unlock()
		if len(got) >= want || time.Now().After(deadline) {
			slices.Sort(got)
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestEveryDispatchEntryAppliesClassSplit(t *testing.T) {
	keepAll := func(fs []Finding) []Finding { return fs }
	entries := []struct {
		name     string
		dispatch func(cfg *config.Config, batch []Finding, gate RepeatGate) error
	}{
		{"Dispatch", func(cfg *config.Config, batch []Finding, _ RepeatGate) error { return Dispatch(cfg, batch) }},
		{"DispatchWithSources", func(cfg *config.Config, batch []Finding, _ RepeatGate) error {
			return DispatchWithSources(cfg, batch, nil)
		}},
		{"DispatchNotices", func(cfg *config.Config, batch []Finding, _ RepeatGate) error { return DispatchNotices(cfg, batch) }},
		{"DispatchNoticesWithNotificationFilter", func(cfg *config.Config, batch []Finding, _ RepeatGate) error {
			return DispatchNoticesWithNotificationFilter(cfg, batch, keepAll)
		}},
		{"DispatchWithEnforcement", func(cfg *config.Config, batch []Finding, _ RepeatGate) error {
			return DispatchWithEnforcement(cfg, batch, nil, batch)
		}},
		{"DispatchWithNotificationFilter", func(cfg *config.Config, batch []Finding, gate RepeatGate) error {
			return DispatchWithNotificationFilter(cfg, batch, nil, nil, batch, keepAll, gate)
		}},
	}
	batch := []Finding{appliedBlockNotice, classTestAlert}
	for _, entry := range entries {
		t.Run(entry.name, func(t *testing.T) {
			isolateAuditManager(t)
			audit := &managedTestSink{name: "jsonl"}
			openJSONLAuditSink = func(string) (AuditSink, error) { return audit, nil }
			mailer := installFakeMailer(t)
			var hooks webhookBodies
			cfg := classConfig(t)
			cfg.Alerts.MaxPerHour = 10
			cfg.Alerts.AuditLog.File.Enabled = true
			cfg.Alerts.AuditLog.File.Path = "unused"
			cfg.Alerts.Email.Enabled = true
			cfg.Alerts.Email.To = []string{"ops@example.com"}
			cfg.Alerts.Email.From = "csm@example.com"
			cfg.Alerts.Email.SMTP = "192.0.2.25:25"
			cfg.Alerts.Webhook.Enabled = true
			cfg.Alerts.Webhook.URL = hooks.server(t).URL
			gate := newMapGate()
			summary := installSummaryHook(t)

			if err := entry.dispatch(cfg, append([]Finding(nil), batch...), gate); err != nil {
				t.Fatal(err)
			}
			if calls := summary.snapshot(); len(calls) != 1 || !slices.Equal(findingKeys(calls[0]), findingKeys([]Finding{appliedBlockNotice})) {
				t.Errorf("summary calls = %v, want exactly the applied block", calls)
			}
			for channel, bodies := range map[string][]string{"email": mailer.messages(), "webhook": hooks.snapshot()} {
				if len(bodies) != 1 || !strings.Contains(bodies[0], "test_alert") || strings.Contains(bodies[0], "AUTO-BLOCK") {
					t.Errorf("%s bodies = %q, want one carrying only test_alert", channel, bodies)
				}
			}
			for _, offered := range gate.offered {
				for _, f := range offered {
					if f.Check == "auto_block" {
						t.Errorf("repeat gate was offered the applied block notice")
					}
				}
			}
			CloseAuditSinks()
			if got := slices.Sorted(slices.Values(audit.checks)); !slices.Equal(got, []string{"auto_block", "test_alert"}) {
				t.Errorf("audit checks = %v, want both findings", got)
			}

			t.Cleanup(closePhpanelQueuesForTest)
			var panel panelChecks
			panelCfg := classConfig(t)
			panelCfg.Alerts.MaxPerHour = 10
			panelCfg.Alerts.Webhook.Enabled = true
			panelCfg.Alerts.Webhook.Type = "phpanel"
			panelCfg.Alerts.Webhook.URL = panel.server(t).URL
			panelCfg.Alerts.Webhook.HMACSecret = "secret"
			if err := entry.dispatch(panelCfg, append([]Finding(nil), batch...), newMapGate()); err != nil {
				t.Fatal(err)
			}
			if got := panel.waitFor(t, 2); !slices.Equal(got, []string{"auto_block", "test_alert"}) {
				t.Errorf("phpanel queue delivered %v, want both findings", got)
			}
		})
	}
}

// disabled_checks mutes email only: the webhook still carries a muted
// immediate finding, and a muted summary finding is still counted.
func TestDisabledChecksStayEmailOnly(t *testing.T) {
	cfg := classConfig(t)
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"ops@example.com"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = "192.0.2.25:25"
	cfg.Alerts.Email.DisabledChecks = []string{"test_alert", "challenge_route"}
	mailer := installFakeMailer(t)
	var hooks webhookBodies
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = hooks.server(t).URL
	summary := installSummaryHook(t)
	route := Finding{Check: "challenge_route", Severity: Warning, Message: "CHALLENGE: 203.0.113.42 sent to PoW challenge (expires in 30m0s)"}

	if err := Dispatch(cfg, []Finding{classTestAlert, route}); err != nil {
		t.Fatal(err)
	}
	if got := mailer.count(); got != 0 {
		t.Errorf("emails = %d, want 0 with every immediate check muted", got)
	}
	if bodies := hooks.snapshot(); len(bodies) != 1 || !strings.Contains(bodies[0], "test_alert") || strings.Contains(bodies[0], "CHALLENGE") {
		t.Errorf("webhook bodies = %q, want only the muted immediate finding", bodies)
	}
	if calls := summary.snapshot(); len(calls) != 1 || !slices.Equal(findingKeys(calls[0]), findingKeys([]Finding{route})) {
		t.Errorf("summary hook calls = %v, want the muted challenge counted once", calls)
	}
}
