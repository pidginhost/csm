package webui

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
)

// Operator ruling 2 (1.5c-3b): the blocked list shows an executed
// admission block from the firewall state, though the tracker never named
// the address.
func TestAPIBlockedIPsListsAnAdmissionBlock(t *testing.T) {
	s := newTestServer(t, "tok")
	dir := s.cfg.StatePath
	data, err := json.Marshal(firewall.FirewallState{Blocked: []firewall.BlockedEntry{{
		IP: "203.0.113.55", Reason: "CSM auto-block: ssh_brute", Source: firewall.SourceAutoResponse,
		ActionID: "act_" + strings.Repeat("5", 32), BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(dir, "firewall"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "firewall", "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "blocked_ips.json"), []byte(`{"ips":[{"ip":"198.51.100.55","expires_at":"2099-01-01T00:00:00Z"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.apiBlockedIPs(w, httptest.NewRequest("GET", "/", nil))
	var got struct {
		Items []blockedView `json:"items"`
		Total int           `json:"total"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	if got.Total != 1 || len(got.Items) != 1 || got.Items[0].IP != "203.0.113.55" || got.Items[0].Source != firewall.SourceAutoResponse {
		t.Fatalf("blocked list = %+v; want only the admission block from the engine state", got)
	}
}
