package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestApiCapabilities_ReturnsList(t *testing.T) {
	s := &Server{cfg: capsTestCfg(), startTime: capsTestTime()}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	rec := httptest.NewRecorder()
	s.apiCapabilities(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Capabilities []string `json:"capabilities"`
		Version      string   `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Capabilities) == 0 {
		t.Fatal("expected non-empty capability list")
	}
	if !capsContains(got.Capabilities, "capabilities.v1") {
		t.Fatalf("capabilities.v1 should always be present, got %v", got.Capabilities)
	}
	for _, want := range []string{"webhook.phpanel.v1", "events.sse.v1", "token.scope.readonly.v1", "audit.fields.tenant.v1"} {
		if !capsContains(got.Capabilities, want) {
			t.Errorf("missing %q in capabilities, got %v", want, got.Capabilities)
		}
	}
	for _, want := range []string{"mail.source.journal.v1", "mail.brute.account_key.v1", "ti.source.rspamd.v1"} {
		if !capsContains(got.Capabilities, want) {
			t.Errorf("missing %q in capabilities, got %v", want, got.Capabilities)
		}
	}
	for _, want := range []string{"auto_response.dry_run.v1", "infra_ips.guard.v1", "store.backup.v1"} {
		if !capsContains(got.Capabilities, want) {
			t.Errorf("missing %q in capabilities, got %v", want, got.Capabilities)
		}
	}
}

func capsContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

func capsTestCfg() *config.Config { return &config.Config{Hostname: "test"} }
func capsTestTime() time.Time     { return time.Now().Add(-1 * time.Hour) }
