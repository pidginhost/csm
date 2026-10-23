package alert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

const testFindingContext = "ModSecurity is disabled for account alice (all domains) (set in /etc/apache2/conf.d/userdata/ssl/2_4/alice/modsec.conf): requests there are not filtered and leave no modsec audit record."

func contextFinding() Finding {
	return Finding{
		Severity:  Critical,
		Check:     "webshell",
		Message:   "Known webshell found: /home/alice/public_html/x.php",
		Details:   "Size: 10",
		FilePath:  "/home/alice/public_html/x.php",
		TenantID:  "alice",
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

// Context is background the condition does not rest on. When it changes the
// finding must keep every identity: alert dedup, dismissals and baselines key
// on Key and Fingerprint, the audit log on its finding and receipt IDs.
func TestFindingContextIsNotPartOfIdentity(t *testing.T) {
	plain := contextFinding()
	annotated := plain
	annotated.Context = testFindingContext

	if plain.Key() != annotated.Key() {
		t.Errorf("Key changed: %q -> %q", plain.Key(), annotated.Key())
	}
	if plain.Fingerprint() != annotated.Fingerprint() {
		t.Errorf("Fingerprint changed: %q -> %q", plain.Fingerprint(), annotated.Fingerprint())
	}
	if FindingID(plain) != FindingID(annotated) {
		t.Errorf("audit finding_id changed")
	}
	if auditObservationKey(plain) != auditObservationKey(annotated) {
		t.Errorf("audit receipt identity changed")
	}
	if got := Deduplicate([]Finding{plain, annotated}); len(got) != 1 {
		t.Errorf("Deduplicate kept %d copies of one finding", len(got))
	}
}

// Every place an operator reads a finding shows its context: the email and
// text webhook body, the JSON the phpanel webhook, event stream and scan job
// reports carry, and the audit log record.
func TestFindingContextReachesEveryRendering(t *testing.T) {
	f := contextFinding()
	f.Context = testFindingContext

	if body := FormatAlert("host.example.com", []Finding{f}); !strings.Contains(body, testFindingContext) {
		t.Errorf("alert body lacks the context:\n%s", body)
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Finding
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.Context != testFindingContext {
		t.Errorf("JSON round trip lost the context: %s (%v)", raw, err)
	}
	if got := NewAuditEvent("host.example.com", f).Context; got != testFindingContext {
		t.Errorf("audit event context = %q", got)
	}

	var posted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		posted = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := &config.Config{Hostname: "host.example.com"}
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.Type = "phpanel"
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.HMACSecret = "panel-shared-secret"
	if err := SendPhpanelWebhookFinding(cfg, f); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Finding Finding `json:"finding"`
	}
	if err := json.Unmarshal([]byte(posted), &payload); err != nil || payload.Finding.Context != testFindingContext {
		t.Errorf("phpanel webhook body lacks the context: %s (%v)", posted, err)
	}
}

// A finding without context renders exactly as before.
func TestFindingWithoutContextRendersUnchanged(t *testing.T) {
	f := contextFinding()
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"context"`) {
		t.Errorf("empty context serialized: %s", raw)
	}
	want := "[CRITICAL] webshell - Known webshell found: /home/alice/public_html/x.php\n  Size: 10\n  Time: 2026-01-02 03:04:05"
	if got := f.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
