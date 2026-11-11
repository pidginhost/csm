package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// A host refresh belongs to the save attempt, before config publication,
// even when the saved setting needs a restart or the save fails.
func TestSettingsSaveHookPrecedesEverySaveOutcome(t *testing.T) {
	for _, tc := range []struct {
		name, section, changes string
		status                 int
		brokenConfig           bool
	}{
		{"live", "auto_response", `{"max_blocks_per_hour":75}`, http.StatusOK, false},
		{"unchanged", "auto_response", `{"max_blocks_per_hour":50}`, http.StatusOK, false},
		{"restart", "challenge", `{"enabled":true}`, http.StatusOK, false},
		{"invalid setting", "auto_response", `{"not_a_setting":true}`, http.StatusUnprocessableEntity, false},
		{"unreadable config", "auto_response", `{"max_blocks_per_hour":75}`, http.StatusInternalServerError, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, path := newSettingsTestServer(t, "", `hostname: host.example
auto_response:
  max_blocks_per_hour: 50
challenge:
  enabled: false
`)
			before := config.Active()
			calls := 0
			s.SetSettingsSaveHook(func() {
				calls++
				if config.Active() != before {
					t.Error("host refresh ran after config publication")
				}
			})
			if tc.brokenConfig {
				// Opening a directory for config reading fails without depending
				// on permissions that a root test runner could bypass.
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			req := httptest.NewRequest(http.MethodPost, settingsURLPrefix+tc.section, strings.NewReader(`{"changes":`+tc.changes+`}`))
			req.Header.Set("If-Match", before.Integrity.ConfigHash)
			w := httptest.NewRecorder()
			s.apiSettingsPost(w, req)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d; body = %s", w.Code, tc.status, w.Body.String())
			}
			if calls != 1 {
				t.Fatalf("host refresh ran %d times, want 1", calls)
			}
		})
	}
}

func TestSettingsSaveHookRunsWhenRollbackRefusesSave(t *testing.T) {
	s, path := newSettingsTestServer(t, "", "hostname: host.example\n")
	mgr := installRollbackManager(t, s.cfg.StatePath, path)
	if _, err := mgr.Apply([]byte("hostname: host.example\n"), []byte("hostname: next.example\n"), time.Minute, "test"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.SetSettingsSaveHook(func() { calls++ })
	req := httptest.NewRequest(http.MethodPost, settingsURLPrefix+"thresholds", strings.NewReader(`{"changes":{}}`))
	req.Header.Set("If-Match", "unused")
	w := httptest.NewRecorder()
	s.apiSettingsPost(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
	if calls != 1 {
		t.Fatalf("host refresh ran %d times, want 1", calls)
	}
}
