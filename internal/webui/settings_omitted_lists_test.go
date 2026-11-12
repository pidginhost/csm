package webui

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
	"gopkg.in/yaml.v3"
)

func TestSettingsPreserveOmittedLists(t *testing.T) {
	for _, tc := range []struct {
		name, ports, users string
	}{
		{name: "absent"},
		{name: "null", ports: "backdoor_ports:\n", users: "  smtp_allow_users:\n"},
		{name: "empty", ports: "backdoor_ports: []\n", users: "  smtp_allow_users: []\n"},
		{name: "custom", ports: "backdoor_ports: [1234]\n", users: "  smtp_allow_users: [alice]\n"},
	} {
		for _, tentative := range []bool{false, true} {
			name := tc.name + "/save"
			if tentative {
				name = tc.name + "/rollback"
			}
			t.Run(name, func(t *testing.T) {
				main := []byte(tc.ports + firewallSettingsTestYAML() + tc.users + "integrity:\n  binary_hash: ''\n  config_hash: ''\n  confd_hash: ''\n")
				token := rand.Text()
				main, err := config.YAMLEdit(main, []config.YAMLChange{{Path: []string{"webui", "auth_token"}, Value: token}})
				if err != nil {
					t.Fatal(err)
				}
				s, path := newSettingsTestServer(t, token, string(main))
				// The shared helper marshals defaults. Restore and sign the raw
				// input so absence is actually exercised by this save.
				if writeErr := os.WriteFile(path, main, 0o600); writeErr != nil {
					t.Fatal(writeErr)
				}
				if _, _, signErr := integrity.SignConfigFilePreserving(path, "", ""); signErr != nil {
					t.Fatal(signErr)
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				want, err := config.Load(path)
				if err != nil {
					t.Fatal(err)
				}
				config.SetActive(want)

				var revert func()
				handler := s.apiSettingsPost
				url := "/api/v1/settings/firewall"
				if tentative {
					mgr := installRollbackManager(t, s.cfg.StatePath, path)
					s.restartDaemon = func() ([]byte, error) { return nil, nil }
					handler = s.apiFirewallTentativeApply
					url += "/tentative-apply"
					revert = func() {
						if revertErr := mgr.Revert(context.Background()); revertErr != nil {
							t.Fatal(revertErr)
						}
						got, readErr := os.ReadFile(path)
						if readErr != nil {
							t.Fatal(readErr)
						}
						if !bytes.Equal(got, before) {
							t.Error("rollback did not restore the original bytes")
						}
					}
				}

				getW := httptest.NewRecorder()
				s.apiSettingsGet(getW, httptest.NewRequest(http.MethodGet, "/api/v1/settings/firewall", nil))
				if getW.Code != http.StatusOK {
					t.Fatalf("GET: %d %s", getW.Code, getW.Body.String())
				}
				req := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"changes":{"log_dropped":false}}`))
				req.Header.Set("If-Match", getW.Header().Get("ETag"))
				w := httptest.NewRecorder()
				handler(w, req)
				if w.Code != http.StatusOK {
					t.Fatalf("POST: %d %s", w.Code, w.Body.String())
				}
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				for _, key := range []string{"backdoor_ports", "smtp_allow_users"} {
					oldValue, oldPresent := rawOmittedList(t, before, key)
					newValue, newPresent := rawOmittedList(t, after, key)
					if oldPresent != newPresent || !reflect.DeepEqual(oldValue, newValue) {
						t.Errorf("save changed the raw state of %s", key)
					}
				}
				got, err := config.Load(path)
				if err != nil {
					t.Fatal(err)
				}
				if got.Firewall.LogDropped {
					t.Error("submitted setting was not saved")
				}
				if !reflect.DeepEqual(got.BackdoorPorts, want.BackdoorPorts) || !reflect.DeepEqual(got.Firewall.SMTPAllowUsers, want.Firewall.SMTPAllowUsers) {
					t.Error("save changed the effective lists")
				}
				if revert != nil {
					revert()
					after = before
				}

				// An explicit clear must disable the extra senders, including
				// defaults selected by an omitted or null value.
				clearReq := httptest.NewRequest(http.MethodPost, url, bytes.NewBufferString(`{"changes":{"smtp_allow_users":[]}}`))
				clearReq.Header.Set("If-Match", integrity.HashConfigStableBytes(after))
				clearW := httptest.NewRecorder()
				handler(clearW, clearReq)
				if clearW.Code != http.StatusOK {
					t.Fatalf("clear senders: %d %s", clearW.Code, clearW.Body.String())
				}
				cleared, err := config.Load(path)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(cleared.Firewall.SMTPAllowUsers, []string{}) {
					t.Error("explicit clear did not persist an empty sender list")
				}
				if !reflect.DeepEqual(cleared.BackdoorPorts, want.BackdoorPorts) {
					t.Error("clearing senders changed the backdoor port list")
				}
				if revert != nil {
					revert()
				}
			})
		}
	}
}

func rawOmittedList(t *testing.T, data []byte, key string) (any, bool) {
	t.Helper()
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if key == "smtp_allow_users" {
		raw = raw["firewall"].(map[string]any)
	}
	value, present := raw[key]
	return value, present
}
