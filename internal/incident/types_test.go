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
	for _, key := range []string{"account", "domain", "mailbox", "summary", "compound_flags"} {
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
		ID:            "i_abc",
		Kind:          KindMailboxTakeover,
		Status:        StatusContained,
		Severity:      alert.Critical,
		Account:       "alice",
		Domain:        "example.com",
		Mailbox:       "alice@example.com",
		Summary:       "outbound spam from alice@example.com",
		Findings:      []string{"f1", "f2"},
		CompoundFlags: CompoundFlags{Webshell: true},
		CreatedAt:     time.Unix(1700000000, 0).UTC(),
		UpdatedAt:     time.Unix(1700000600, 0).UTC(),
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
		`"compound_flags":{"webshell":true}`,
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
		KindWebAttack,
		KindMailboxTakeover,
		KindPostExploitProcess,
		KindHostIntegrityRisk,
		KindCredentialSpray,
		KindHostTakeover,
	} {
		if strings.Contains(string(k), " ") || strings.Contains(string(k), "-") {
			t.Errorf("kind %q must be snake_case", k)
		}
	}
}

func TestIncidentJSONRoundTrip(t *testing.T) {
	want := Incident{
		ID:        "i_abc",
		Kind:      KindMailboxTakeover,
		Status:    StatusContained,
		Severity:  alert.Critical,
		Account:   "alice",
		Findings:  []string{"f1", "f2"},
		CreatedAt: time.Unix(1700000000, 0).UTC(),
		UpdatedAt: time.Unix(1700000600, 0).UTC(),
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Incident
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != want.ID || got.Kind != want.Kind || got.Status != want.Status {
		t.Errorf("identity fields lost: got=%+v want=%+v", got, want)
	}
	if got.Severity != want.Severity {
		t.Errorf("Severity lost: got=%v want=%v", got.Severity, want.Severity)
	}
	if got.Account != want.Account {
		t.Errorf("Account: %q vs %q", got.Account, want.Account)
	}
	if len(got.Findings) != 2 || got.Findings[0] != "f1" {
		t.Errorf("Findings round-trip: %+v", got.Findings)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("CreatedAt: %v vs %v", got.CreatedAt, want.CreatedAt)
	}
}

func TestIncidentJSONUnmarshalUnknownSeverityFails(t *testing.T) {
	raw := []byte(`{"id":"i","kind":"web_account_compromise","status":"open","severity":"BOGUS","created_at":"2026-05-08T00:00:00Z","updated_at":"2026-05-08T00:00:00Z"}`)
	var got Incident
	err := json.Unmarshal(raw, &got)
	if err == nil {
		t.Fatal("expected error on unknown severity, got nil")
	}
}
