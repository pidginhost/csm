package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/maillog"
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
	if maillog.JournalSupported() && !capsContains(got.Capabilities, "mail.source.journal.v1") {
		t.Errorf("missing %q in capabilities, got %v", "mail.source.journal.v1", got.Capabilities)
	}
	if !maillog.JournalSupported() && capsContains(got.Capabilities, "mail.source.journal.v1") {
		t.Errorf("journal capability advertised by a build without journal support: %v", got.Capabilities)
	}
	for _, want := range []string{"mail.brute.account_key.v1", "ti.source.rspamd.v1"} {
		if !capsContains(got.Capabilities, want) {
			t.Errorf("missing %q in capabilities, got %v", want, got.Capabilities)
		}
	}
	for _, want := range []string{"auto_response.dry_run.v1", "infra_ips.guard.v1", "store.backup.v1"} {
		if !capsContains(got.Capabilities, want) {
			t.Errorf("missing %q in capabilities, got %v", want, got.Capabilities)
		}
	}
	for _, want := range []string{"ti.source.upstream.v1"} {
		if !capsContains(got.Capabilities, want) {
			t.Errorf("missing %q in capabilities, got %v", want, got.Capabilities)
		}
	}
	for _, want := range []string{"verdict.callback.v1", "systemd.dropin.example.v1"} {
		if !capsContains(got.Capabilities, want) {
			t.Errorf("missing %q in capabilities, got %v", want, got.Capabilities)
		}
	}
	for _, want := range []string{"webui.prefs.v1", "webui.undo.v1"} {
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
