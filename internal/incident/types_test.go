package incident

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func TestIncidentJSONOmitsZeroFields(t *testing.T) {
	inc := Incident{ID: "i_abc", Kind: KindWebAccountCompromise, Status: StatusOpen, Severity: alert.High}
	b, err := json.Marshal(inc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, key := range []string{"account", "domain", "mailbox", "summary"} {
		if strings.Contains(s, `"`+key+`"`) {
			t.Errorf("zero-value Incident should omit %q, got %s", key, s)
		}
	}
	for _, want := range []string{`"id":"i_abc"`, `"kind":"web_account_compromise"`, `"status":"open"`, `"severity":"HIGH"`} {
		if !strings.Contains(s, want) {
			t.Errorf("required field missing %q in %s", want, s)
		}
	}
}

func TestIncidentJSONIncludesPopulatedFields(t *testing.T) {
	inc := Incident{
		ID:        "i_abc",
		Kind:      KindMailboxTakeover,
		Status:    StatusContained,
		Severity:  alert.Critical,
		Account:   "alice",
		Domain:    "example.com",
		Mailbox:   "alice@example.com",
		Summary:   "outbound spam from alice@example.com",
		Findings:  []string{"f1", "f2"},
		CreatedAt: time.Unix(1700000000, 0).UTC(),
		UpdatedAt: time.Unix(1700000600, 0).UTC(),
	}
	b, err := json.Marshal(inc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		`"account":"alice"`,
		`"domain":"example.com"`,
		`"mailbox":"alice@example.com"`,
		`"summary":"outbound spam from alice@example.com"`,
		`"findings":["f1","f2"]`,
		`"kind":"mailbox_takeover"`,
		`"status":"contained"`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("expected %q in %s", want, b)
		}
	}
}

func TestStatusValuesAreLowercase(t *testing.T) {
	for _, s := range []Status{StatusOpen, StatusContained, StatusResolved, StatusDismissed} {
		if string(s) != strings.ToLower(string(s)) {
			t.Errorf("status %q must be lowercase per spec", s)
		}
	}
}

func TestKindValuesUseSnakeCase(t *testing.T) {
	for _, k := range []Kind{
		KindWebAccountCompromise,
		KindMailboxTakeover,
		KindPostExploitProcess,
		KindHostIntegrityRisk,
	} {
		if strings.Contains(string(k), " ") || strings.Contains(string(k), "-") {
			t.Errorf("kind %q must be snake_case", k)
		}
	}
}
