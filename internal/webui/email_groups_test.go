package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Helper: build a finding with the email-relevant identity fields.
func emailFinding(check string, sev alert.Severity, mailbox, domain, ip string, ts time.Time) alert.Finding {
	return alert.Finding{
		Severity:  sev,
		Check:     check,
		Message:   check + " event",
		Mailbox:   mailbox,
		Domain:    domain,
		SourceIP:  ip,
		Timestamp: ts,
	}
}

func TestEmailGroupsAuthFailureMergesByMailbox(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "example.com", "192.0.2.1", now.Add(-3*time.Minute)),
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "example.com", "192.0.2.2", now.Add(-2*time.Minute)),
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "example.com", "192.0.2.1", now.Add(-1*time.Minute)),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "")
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1: %+v", len(groups), groups)
	}
	g := groups[0]
	if g.Kind != "auth_failure" {
		t.Errorf("kind = %q, want auth_failure", g.Kind)
	}
	if g.Title != "jane@example.com" {
		t.Errorf("title = %q, want mailbox", g.Title)
	}
	if g.Count != 3 {
		t.Errorf("count = %d, want 3", g.Count)
	}
	if len(g.IPs) != 2 {
		t.Errorf("ips = %v, want 2 unique", g.IPs)
	}
	if g.Subject != "mailbox" {
		t.Errorf("subject = %q, want mailbox", g.Subject)
	}
}

func TestEmailGroupsAuthFailureFallsBackToSourceIP(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.High, "", "", "203.0.113.10", now.Add(-2*time.Minute)),
		emailFinding("email_auth_failure_realtime", alert.High, "", "", "203.0.113.10", now.Add(-1*time.Minute)),
		emailFinding("email_auth_failure_realtime", alert.High, "", "", "203.0.113.20", now),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "")
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2 (one per IP): %+v", len(groups), groups)
	}
	for _, g := range groups {
		if g.Subject != "ip" {
			t.Errorf("subject = %q, want ip when mailbox is absent", g.Subject)
		}
	}
}

func TestEmailGroupsSpamOutbreakDedupesUnknownMailbox(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("email_spam_outbreak", alert.Critical, "", "example.com", "", now.Add(-3*time.Minute)),
		emailFinding("email_spam_outbreak", alert.Critical, "", "example.com", "", now.Add(-2*time.Minute)),
		emailFinding("email_spam_outbreak", alert.Critical, "", "example.com", "", now.Add(-1*time.Minute)),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "")
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1 (deduped): %+v", len(groups), groups)
	}
	if groups[0].Count != 3 {
		t.Errorf("count = %d, want 3", groups[0].Count)
	}
}

func TestEmailGroupsKindFilterScopesResults(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.High, "a@example.com", "", "192.0.2.1", now),
		emailFinding("email_compromised_account", alert.Critical, "b@example.com", "", "", now),
		emailFinding("email_spam_outbreak", alert.Critical, "c@example.com", "", "", now),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "auth_failure")
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1 auth_failure", len(groups))
	}
	if groups[0].Kind != "auth_failure" {
		t.Errorf("kind = %q, want auth_failure", groups[0].Kind)
	}
}

func TestEmailGroupsRespectsDateRange(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		// Outside the requested window: too old.
		emailFinding("email_auth_failure_realtime", alert.High, "old@example.com", "", "192.0.2.1", now.Add(-25*time.Hour)),
		// In window.
		emailFinding("email_auth_failure_realtime", alert.High, "new@example.com", "", "192.0.2.2", now.Add(-1*time.Hour)),
	}
	groups := buildEmailGroups(in, now.Add(-12*time.Hour), now, "")
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1 (window filter)", len(groups))
	}
	if groups[0].Title != "new@example.com" {
		t.Errorf("title = %q, want new@example.com", groups[0].Title)
	}
}

func TestEmailGroupsIgnoresNonEmailFindings(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("webshell", alert.Critical, "", "", "", now),
		emailFinding("waf_status", alert.Warning, "", "", "", now),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "")
	if len(groups) != 0 {
		t.Fatalf("got %d groups, want 0 for non-email checks: %+v", len(groups), groups)
	}
}

func TestEmailGroupsSortsBySeverityThenLastSeen(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.Warning, "low@example.com", "", "192.0.2.1", now),
		emailFinding("email_compromised_account", alert.Critical, "crit@example.com", "", "", now.Add(-30*time.Minute)),
		emailFinding("email_compromised_account", alert.Critical, "newer@example.com", "", "", now),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "")
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(groups))
	}
	if groups[0].Severity != int(alert.Critical) {
		t.Errorf("first group severity = %d, want critical", groups[0].Severity)
	}
	if groups[0].Title != "newer@example.com" {
		t.Errorf("first crit group should be newest: got %q", groups[0].Title)
	}
	if groups[2].Severity != int(alert.Warning) {
		t.Errorf("last group severity = %d, want warning", groups[2].Severity)
	}
}

func TestEmailGroupsAggregatesQueueAlerts(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("mail_queue", alert.High, "", "", "", now.Add(-3*time.Minute)),
		emailFinding("mail_queue", alert.High, "", "", "", now.Add(-2*time.Minute)),
		emailFinding("mail_per_account", alert.Warning, "noisy@example.com", "", "", now.Add(-1*time.Minute)),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "queue_alert")
	if len(groups) != 2 {
		t.Fatalf("got %d queue groups, want 2 (mail_queue + mail_per_account)", len(groups))
	}
}

func TestEmailGroupsIncludesCurrentEmailDetectorChecks(t *testing.T) {
	now := time.Now()
	cases := []struct {
		check string
		kind  string
	}{
		{check: "exim_frozen_realtime", kind: "queue_alert"},
		{check: "email_av_degraded", kind: "malware"},
		{check: "email_av_timeout", kind: "malware"},
		{check: "email_av_parse_error", kind: "malware"},
		{check: "email_av_quarantine_error", kind: "malware"},
		{check: "mail_bruteforce", kind: "auth_failure"},
		{check: "smtp_bruteforce", kind: "auth_failure"},
		{check: "smtp_probe_abuse", kind: "auth_failure"},
		{check: "mail_account_compromised", kind: "compromised_account"},
		{check: "email_suspicious_forwarder", kind: "compromised_account"},
		{check: "email_rate_critical", kind: "spam_outbreak"},
	}

	for _, tc := range cases {
		t.Run(tc.check, func(t *testing.T) {
			groups := buildEmailGroups(
				[]alert.Finding{emailFinding(tc.check, alert.High, "user@example.com", "example.com", "192.0.2.10", now)},
				now.Add(-1*time.Hour),
				now,
				"",
			)
			if len(groups) != 1 {
				t.Fatalf("got %d groups, want 1 for %s", len(groups), tc.check)
			}
			if groups[0].Kind != tc.kind {
				t.Fatalf("kind = %q, want %q", groups[0].Kind, tc.kind)
			}
		})
	}
}

func TestEmailGroupsEmptyInput(t *testing.T) {
	groups := buildEmailGroups(nil, time.Time{}, time.Now(), "")
	if len(groups) != 0 {
		t.Fatalf("nil input should produce no groups, got %d", len(groups))
	}
}

func TestAPIEmailGroupsRejectsNonGet(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	s.apiEmailGroups(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/groups", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestAPIEmailGroupsReturnsJSON(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "", "192.0.2.5", now.Add(-1*time.Minute)),
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "", "192.0.2.6", now),
	})

	w := httptest.NewRecorder()
	s.apiEmailGroups(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/groups", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}

	var resp emailGroupsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	if len(resp.Groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(resp.Groups))
	}
	if resp.Groups[0].Title != "jane@example.com" {
		t.Errorf("title = %q", resp.Groups[0].Title)
	}
	if resp.Groups[0].Count != 2 {
		t.Errorf("count = %d, want 2", resp.Groups[0].Count)
	}
}

func TestAPIEmailGroupsDateOnlyToIncludesWholeDay(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	day := time.Now().AddDate(0, 0, -1)
	ts := time.Date(day.Year(), day.Month(), day.Day(), 15, 30, 0, 0, time.Local)
	s.store.AppendHistory([]alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.High, "same-day@example.com", "", "192.0.2.8", ts),
	})

	date := ts.Format("2006-01-02")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/email/groups?from="+date+"&to="+date, nil)
	s.apiEmailGroups(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp emailGroupsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	if len(resp.Groups) != 1 {
		t.Fatalf("groups = %d, want 1 for date-only same-day range: %+v", len(resp.Groups), resp.Groups)
	}
	if resp.Groups[0].Title != "same-day@example.com" {
		t.Errorf("title = %q, want same-day@example.com", resp.Groups[0].Title)
	}
}

func TestAPIEmailGroupsReadScopeAccess(t *testing.T) {
	s := newTestServerWithBbolt(t, "admin-tok")
	s.cfg.WebUI.Tokens = []config.WebUIToken{
		{Name: "admin", Token: "admin-tok", Scope: "admin"},
		{Name: "read-only", Token: "read-tok", Scope: "read"},
	}

	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "", "192.0.2.7", now),
	})

	handler := s.requireRead(http.HandlerFunc(s.apiEmailGroups))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/email/groups", nil)
	req.Header.Set("Authorization", "Bearer read-tok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("read-scope GET status = %d, body = %s", w.Code, w.Body.String())
	}
}
