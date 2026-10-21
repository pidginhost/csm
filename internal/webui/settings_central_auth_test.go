package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/integrity"
)

func TestSettingsPOSTCentralAuthOrigin(t *testing.T) {
	const centralConfig = `hostname: node.example.net
alerts:
  email:
    enabled: true
    to: [ops@example.net]
    from: csm@example.net
    smtp: smtp.example.net:587
integrity:
  binary_hash: ""
  config_hash: ""
  confd_hash: ""
reputation:
  central:
    enabled: true
    set_url: https://abuse.example.net/decisions
    auth_target: central
`
	const reportConfig = `  report:
    enabled: false
    targets:
      - name: central
        url: https://abuse.example.net/report
        transport: ed25519
        node_id: n_000000000000000000000001
        key_id: k_000000000000000000000002
        key_env: CSM_TEST_NODE_KEY
      - name: backup
        url: https://abuse.example.net:443/report
        transport: ed25519
        node_id: n_000000000000000000000003
        key_id: k_000000000000000000000004
        key_env: CSM_TEST_NODE_KEY
      - name: other
        url: https://other.example.net/report
        transport: ed25519
        node_id: n_000000000000000000000005
        key_id: k_000000000000000000000006
        key_env: CSM_TEST_NODE_KEY
`
	for _, dropIn := range []bool{false, true} {
		location := "main"
		if dropIn {
			location = "drop-in"
		}
		t.Run(location, func(t *testing.T) {
			for _, tc := range []struct {
				name, changes, wantURL, wantTarget string
				valid                              bool
			}{
				{"same origin URL", `{"central.set_url":"https://abuse.example.net:443/new"}`, "https://abuse.example.net:443/new", "central", true},
				{"same origin target", `{"central.auth_target":"backup"}`, "https://abuse.example.net/decisions", "backup", true},
				{"matching pair", `{"central.auth_target":"other","central.set_url":"https://other.example.net/decisions"}`, "https://other.example.net/decisions", "other", true},
				{"other host", `{"central.set_url":"https://other.example.net/decisions"}`, "", "", false},
				{"other port", `{"central.set_url":"https://abuse.example.net:8443/decisions"}`, "", "", false},
				{"other scheme", `{"central.set_url":"http://abuse.example.net/decisions"}`, "", "", false},
				{"other target", `{"central.auth_target":"other"}`, "", "", false},
				{"missing target", `{"central.auth_target":"missing"}`, "", "", false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var s *Server
					var path, confDir string
					if dropIn {
						s, path, confDir = newSettingsTestServerWithConfDir(t, "tok", centralConfig, map[string]string{
							"report.yaml": "reputation:\n" + reportConfig,
						})
						// The helper marshals the merged config. Keep targets only
						// in the fragment so loading it does not append duplicates.
						if err := os.WriteFile(path, []byte(centralConfig), 0o600); err != nil {
							t.Fatal(err)
						}
						if _, _, err := integrity.SignConfigFilePreserving(path, confDir, "sha256:testbinary"); err != nil {
							t.Fatal(err)
						}
						effective, err := config.LoadWithDir(path, confDir)
						if err != nil {
							t.Fatal(err)
						}
						config.SetActive(effective)
					} else {
						s, path = newSettingsTestServer(t, "tok", centralConfig+reportConfig)
					}
					for _, result := range config.Validate(config.Active()) {
						if result.Level == "error" {
							t.Fatalf("invalid starting config: %s: %s", result.Field, result.Message)
						}
					}
					before, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					live := config.Active().Reputation
					w := postSettingsChange(t, s, "reputation", tc.changes)
					if config.Active().Reputation.Central != live.Central {
						t.Fatal("central settings changed before restart")
					}
					if !tc.valid {
						if w.Code != http.StatusUnprocessableEntity {
							t.Fatalf("status = %d, want 422: %s", w.Code, w.Body.String())
						}
						if settingsFieldErrors(t, w)["reputation.central.auth_target"] == "" {
							t.Fatalf("missing auth_target validation error: %s", w.Body.String())
						}
						after, readErr := os.ReadFile(path)
						if readErr != nil {
							t.Fatal(readErr)
						}
						if !bytes.Equal(before, after) {
							t.Fatal("rejected settings changed the config on disk")
						}
						return
					}
					if w.Code != http.StatusOK {
						t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
					}
					var result struct {
						PendingRestart bool `json:"pending_restart"`
					}
					if decodeErr := json.Unmarshal(w.Body.Bytes(), &result); decodeErr != nil {
						t.Fatal(decodeErr)
					}
					if !result.PendingRestart {
						t.Fatal("central settings must request a restart")
					}
					disk, err := config.LoadWithDir(path, confDir)
					if err != nil {
						t.Fatal(err)
					}
					if disk.Reputation.Central.SetURL != tc.wantURL || disk.Reputation.Central.AuthTarget != tc.wantTarget {
						t.Fatal("saved central settings do not match the requested values")
					}
				})
			}
		})
	}
}
