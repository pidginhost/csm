package daemon

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

type loginDeliveryTransport struct{ received chan alert.Finding }

func (tr loginDeliveryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var payload struct {
		Finding alert.Finding `json:"finding"`
	}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		return nil, err
	}
	tr.received <- payload.Finding
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}

func TestLoginUpgradeKeepsPhpanelDelivery(t *testing.T) {
	for _, initial := range []bool{false, true} {
		t.Run(map[bool]string{false: "batch", true: "initial"}[initial], func(t *testing.T) {
			received := make(chan alert.Finding, 4)
			t.Cleanup(alert.SetWebhookTransportForTest(loginDeliveryTransport{received}))
			t.Cleanup(alert.ClosePhpanelQueues)
			cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
			cfg.Alerts.Webhook.Enabled = true
			cfg.Alerts.Webhook.Type = "phpanel"
			cfg.Alerts.Webhook.URL = "https://panel.invalid/findings"
			cfg.Alerts.Webhook.HMACSecret = rand.Text()
			st, err := state.Open(cfg.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			d := New(cfg, st, nil, "")
			findings := []alert.Finding{
				{Check: "ftp_login", Severity: alert.Warning, Message: "FTP login", SourceIP: "192.0.2.20"},
				{Check: "cpanel_file_upload_realtime", Severity: alert.Warning, Message: "File Manager write", TenantID: "account"},
			}
			if initial {
				d.respondToInitialScan(cfg, findings)
			} else {
				d.dispatchBatch(findings)
				d.dispatchBatch(findings)
			}
			seen := make(map[string]int)
			for range findings {
				select {
				case f := <-received:
					seen[f.Check]++
				case <-time.After(2 * time.Second):
					t.Fatalf("operator notification filter dropped data-plane findings: %v", seen)
				}
			}
			alert.ClosePhpanelQueues()
			if seen["ftp_login"] != 1 || seen["cpanel_file_upload_realtime"] != 1 || len(received) != 0 {
				t.Fatalf("unexpected or duplicate deliveries: %v, queued=%d", seen, len(received))
			}
		})
	}
}
