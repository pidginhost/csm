package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

func TestEmailCheckListCoversRegistry(t *testing.T) {
	listed := emailCheckSet()
	excluded := map[string]bool{}
	for _, n := range emailCheckExclusions {
		excluded[n] = true
	}
	// A mail check can sit in any category (brute force, health), so the
	// name prefix counts as much as the category.
	for _, name := range checks.AllCheckNames() {
		info, _ := checks.LookupCheck(name)
		relevant := info.Category == checks.CategoryEmail
		for _, prefix := range []string{"mail_", "smtp_", "email_", "exim_", "antispam_"} {
			relevant = relevant || strings.HasPrefix(name, prefix)
		}
		if relevant && !listed[name] && !excluded[name] {
			t.Errorf("%s is email-relevant: add it to emailChecks or emailCheckExclusions", name)
		}
	}
}

func TestEmailCheckListNamesAreRegisteredOnce(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range emailChecks {
		if _, ok := checks.LookupCheck(c.Name); !ok || seen[c.Name] {
			t.Errorf("%s unregistered or duplicated", c.Name)
		}
		seen[c.Name] = true
	}
	for _, n := range emailCheckExclusions {
		if seen[n] {
			t.Errorf("%s both listed and excluded", n)
		}
	}
}

func TestEmailKindsUnchangedForExistingChecks(t *testing.T) {
	want := map[string]string{"mail_bruteforce": "auth_failure", "email_malware": "malware",
		"email_spam_outbreak": "spam_outbreak", "mail_queue": "queue_alert", "email_compromised_account": "compromised_account",
		"antispam_rspamd_down": "", "phishing_page": ""}
	for c, k := range want {
		if got := emailKindForCheck(c); got != k {
			t.Errorf("%s: %q want %q", c, got, k)
		}
	}
}

func TestHistoryScopeEmail(t *testing.T) {
	s := newTestServer(t, "tok")
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		{Severity: alert.Warning, Check: "mail_queue", Message: "queue large", Timestamp: now.Add(-2 * time.Minute)},
		{Severity: alert.High, Check: "waf_status", Message: "WAF off", Timestamp: now.Add(-time.Minute)},
	})

	historyChecks := func(query string) []string {
		t.Helper()
		w := httptest.NewRecorder()
		s.apiHistory(w, httptest.NewRequest(http.MethodGet, "/api/v1/history?"+query, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", query, w.Code, w.Body.String())
		}
		var resp struct {
			Items []struct {
				Check string `json:"check"`
			} `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		var got []string
		for _, it := range resp.Items {
			got = append(got, it.Check)
		}
		return got
	}

	if got := historyChecks("scope=email"); len(got) != 1 || got[0] != "mail_queue" {
		t.Errorf("scope=email returned %v, want [mail_queue]", got)
	}
	if got := historyChecks("scope=email&checks=waf_status"); len(got) != 1 || got[0] != "waf_status" {
		t.Errorf("explicit checks with scope=email returned %v, want [waf_status]", got)
	}
}

func TestEmailChecksEndpointReadScope(t *testing.T) {
	s, tok := newTestServerWithReadToken(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/email/checks", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	s.httpSrv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("read token: status %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Checks []emailCheck `json:"checks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range resp.Checks {
		if c.Name == "mail_bruteforce" {
			found = c.Kind == "auth_failure"
		}
	}
	if !found || len(resp.Checks) != len(emailChecks) {
		t.Errorf("body lacks mail_bruteforce as auth_failure or the full list: %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/checks", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: status %d, want 401", w.Code)
	}
}
