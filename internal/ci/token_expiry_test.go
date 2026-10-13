package ci

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestPackageTokenIssueTime(t *testing.T) {
	script, err := os.ReadFile("../../build/packaging/scripts/postinstall.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, block, ok := strings.Cut(string(script), "# Generate WebUI auth token")
	if !ok {
		t.Fatal("token generation block missing")
	}
	_, block, _ = strings.Cut(block, "\n")
	block, _, ok = strings.Cut(block, "# Upgrade hygiene:")
	if !ok {
		t.Fatal("token generation boundary missing")
	}
	for _, tc := range []struct {
		name                 string
		fresh, olderTemplate bool
	}{
		{"fresh", true, false},
		{"older placeholder", true, true},
		{"reinstall", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := os.ReadFile("../../build/packaging/csm.yaml.default")
			if err != nil {
				t.Fatal(err)
			}
			placeholder := "1"
			if tc.olderTemplate {
				lines := bytes.Split(body, []byte("\n"))
				var kept [][]byte
				for _, line := range lines {
					if !bytes.HasPrefix(line, []byte("  auth_token_issued_at:")) {
						kept = append(kept, line)
					}
				}
				body = bytes.Join(kept, []byte("\n"))
			}
			if !tc.fresh {
				placeholder = "0"
				body = bytes.Replace(body, []byte(`auth_token: ""`), fmt.Appendf(nil, "auth_token: %q", rand.Text()), 1)
				body = bytes.Replace(body, []byte(`auth_token_issued_at: ""`), fmt.Appendf(nil, "auth_token_issued_at: %q", time.Now().Add(-8*24*time.Hour).UTC().Format(time.RFC3339)), 1)
			}
			path := filepath.Join(t.TempDir(), "csm.yaml")
			if writeErr := os.WriteFile(path, body, 0600); writeErr != nil {
				t.Fatal(writeErr)
			}
			before := time.Now().UTC().Truncate(time.Second)
			sed, lookupErr := exec.LookPath("sed")
			if lookupErr != nil {
				t.Fatal(lookupErr)
			}
			bin := t.TempDir()
			// Reject a generated credential in argv without recording its value.
			guard := `#!/bin/bash
for arg in "$@"; do
    if [[ "$arg" == *auth_token* && "$arg" =~ [[:alnum:]]{32} ]]; then
        exit 97
    fi
done
exec "$CSM_TEST_REAL_SED" "$@"
`
			if writeErr := os.WriteFile(filepath.Join(bin, "sed"), []byte(guard), 0700); writeErr != nil {
				t.Fatal(writeErr)
			}
			cmd := exec.Command("bash", "-e", "-c", block)
			cmd.Env = append(os.Environ(), "CONFIG="+path, "WAS_PLACEHOLDER="+placeholder, "CSM_TEST_REAL_SED="+sed, "PATH="+bin+":"+os.Getenv("PATH"))
			if runErr := cmd.Run(); runErr != nil {
				t.Fatal("package token setup failed")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.fresh {
				if !bytes.Equal(after, body) {
					t.Fatal("package reinstall changed an existing credential or issue time")
				}
				return
			}
			cfg, err := config.LoadBytes(after)
			if err != nil {
				t.Fatal("package generated invalid configuration")
			}
			issued, err := time.Parse(time.RFC3339, cfg.WebUI.AuthTokenIssuedAt)
			if err != nil || issued.Before(before) || issued.After(time.Now()) {
				t.Fatal("package did not record the new token's issue time")
			}
			if len(cfg.WebUI.AuthToken) < 32 {
				t.Fatal("package did not generate a usable token")
			}
		})
	}
}
