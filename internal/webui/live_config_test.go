package webui

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// The web UI held the startup *config.Config while a hot reload installed a
// new pointer, so pages and actions kept showing and applying the pre-reload
// thresholds, firewall settings, scan options and alert routing. Handlers
// read the live configuration, falling back to the startup one before any
// reload has happened.
func TestEmailStatsReadsLiveConfigAfterReload(t *testing.T) {
	prevActive := config.Active()
	config.SetActive(nil)
	t.Cleanup(func() { config.SetActive(prevActive) })

	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{}
	s.cfg.Thresholds.MailQueueWarn = 100

	live := &config.Config{StatePath: s.cfg.StatePath, Firewall: &firewall.FirewallConfig{SMTPBlock: true}}
	live.Thresholds.MailQueueWarn = 4321
	live.Thresholds.MailQueueCrit = 8765
	config.SetActive(live)

	rec := httptest.NewRecorder()
	s.apiEmailStats(rec, httptest.NewRequest("GET", "/api/v1/email/stats", nil))
	var resp emailStatsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v: %s", err, rec.Body.String())
	}
	if resp.QueueWarn != 4321 || resp.QueueCrit != 8765 || !resp.SMTPBlock {
		t.Fatalf("email stats served the startup config after a reload: %+v", resp)
	}
}
