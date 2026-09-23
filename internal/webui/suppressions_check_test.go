package webui

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A rule matches a finding's check name exactly. A name no check can emit
// ("webshell*", "web shell") would be saved as a rule that matches nothing.
func TestSuppressionRejectsMalformedCheckNames(t *testing.T) {
	s := newTestServer(t, "tok")
	for _, check := range []string{"webshell*", "web shell", "../webshell", "webshell\n"} {
		body, _ := json.Marshal(map[string]any{"check": check, "all_paths": true})
		if w := postSuppression(t, s, string(body)); w.Code != http.StatusBadRequest {
			t.Errorf("check %q: status %d, want 400", check, w.Code)
		}
	}
	if rules := s.store.LoadSuppressions(); len(rules) != 0 {
		t.Fatalf("malformed names saved rules: %+v", rules)
	}
}

// A well-formed name no known check uses is saved, since other subsystems
// can emit checks the registry does not list, but the response warns so a
// typo is noticed.
func TestSuppressionWarnsAboutUnknownCheckNames(t *testing.T) {
	s := newTestServer(t, "tok")
	s.store.SetLatestFindings([]alert.Finding{{Check: "vendor_emitted_check", Severity: alert.Warning, Timestamp: time.Now()}})
	cases := []struct {
		check string
		warn  bool
	}{
		{"webshell", false},
		{"vendor_emitted_check", false},
		{"webshel", true},
	}
	for _, tc := range cases {
		body, _ := json.Marshal(map[string]any{"check": tc.check, "all_paths": true})
		w := postSuppression(t, s, string(body))
		if w.Code != http.StatusOK {
			t.Fatalf("check %q: status %d: %s", tc.check, w.Code, w.Body.String())
		}
		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if got := resp["warning"] != ""; got != tc.warn {
			t.Errorf("check %q: warning = %q, want warning %v", tc.check, resp["warning"], tc.warn)
		}
	}
}
