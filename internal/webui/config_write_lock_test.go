package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/integrity"
)

// Three endpoints rewrite csm.yaml (settings save, verified-bots save, the
// tentative firewall apply). They used to serialize on three different locks,
// and the firewall path on none, so two operators on different pages could
// interleave read-check-write and one of them silently lost their change even
// with matching If-Match headers. Every csm.yaml writer takes the same lock.
func TestConfigWritersShareOneLock(t *testing.T) {
	s := newTestServer(t, "tok")
	configMu := integrity.ConfigWriteMutex()
	configMu.Lock()

	handlers := map[string]func(chan struct{}){
		"settings": func(done chan struct{}) {
			req := httptest.NewRequest("POST", settingsURLPrefix+"thresholds", strings.NewReader(`{"changes":{}}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("If-Match", `"stale"`)
			s.apiSettingsPost(httptest.NewRecorder(), req)
			close(done)
		},
		"verified_bots": func(done chan struct{}) {
			req := httptest.NewRequest("POST", "/api/v1/verified-bots/apply", strings.NewReader(`{}`))
			s.apiVerifiedBotsApply(httptest.NewRecorder(), req)
			close(done)
		},
		"firewall_tentative": func(done chan struct{}) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/tentative-apply", strings.NewReader(`{}`))
			s.apiFirewallTentativeApply(httptest.NewRecorder(), req)
			close(done)
		},
	}
	dones := map[string]chan struct{}{}
	for name, run := range handlers {
		done := make(chan struct{})
		dones[name] = done
		go run(done)
	}
	for name, done := range dones {
		select {
		case <-done:
			t.Fatalf("%s writer ran without taking the shared config lock", name)
		case <-time.After(150 * time.Millisecond):
		}
	}

	configMu.Unlock()
	for name, done := range dones {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s writer did not proceed after the lock was released", name)
		}
	}
}
