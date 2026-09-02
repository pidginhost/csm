package webui

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// The detail endpoint looked the alert state up under "check:message", but
// state is keyed by Finding.Key(), which folds in a hash of Details (and the
// source IP for IP-keyed checks). Every finding with details therefore showed
// no first/last-seen timestamps. The endpoint resolves the stored finding's
// real key.
func TestFindingDetailUsesStoredFindingKey(t *testing.T) {
	s := newTestServer(t, "tok")
	f := alert.Finding{
		Severity:  alert.Critical,
		Check:     "webshell",
		Message:   "Found /home/alice/shell.php",
		Details:   "Signature: c99 marker",
		FilePath:  "/home/alice/shell.php",
		Timestamp: time.Now(),
	}
	s.store.SetLatestFindings([]alert.Finding{f})
	s.store.Update([]alert.Finding{f})

	q := url.Values{"check": {f.Check}, "message": {f.Message}}
	w := httptest.NewRecorder()
	s.apiFindingDetail(w, httptest.NewRequest("GET", "/?"+q.Encode(), nil))
	var resp struct {
		FirstSeen string `json:"first_seen"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v: %s", err, w.Body.String())
	}
	if resp.FirstSeen == "" {
		t.Fatalf("finding with details has no first_seen in its detail view: %s", w.Body.String())
	}
}
