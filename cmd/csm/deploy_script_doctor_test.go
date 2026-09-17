package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An operator copy of a deploy script drifts silently: it is not shipped, not
// upgraded, and nothing reads it until the next deploy. A copy that predates
// fail-closed verification installs release artifacts without checking their
// signature, so the host must report it before that deploy happens.
func TestDoctorReportsDeployScriptsThatSkipVerification(t *testing.T) {
	const legacy = `verify_signature() {
    if ! command -v openssl >/dev/null 2>&1; then
        echo "  WARNING: openssl not found, skipping signature check" >&2
        return 0
    fi
}`
	const current = `verify_signature() {
    if openssl_verifies_ed25519; then
        verifier=openssl
    else
        die "no Ed25519 verifier available: install OpenSSL 3.0+ or python3-cryptography"
    fi
}`
	for _, tc := range []struct {
		name, body string
		wantFail   bool
	}{
		{"legacy skip path", legacy, true},
		{"fail-closed", current, false},
		{"unrelated script", "#!/bin/bash\necho hello\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			script := filepath.Join(dir, "deploy-csm.sh")
			if err := os.WriteFile(script, []byte("#!/bin/bash\n"+tc.body+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			old := deployScriptSearchPaths
			t.Cleanup(func() { deployScriptSearchPaths = old })
			deployScriptSearchPaths = []string{dir}

			checks := deployScriptDoctorChecks()
			if !tc.wantFail {
				for _, c := range checks {
					if c.Status == "fail" {
						t.Fatalf("clean script reported: %+v", c)
					}
				}
				return
			}
			if len(checks) != 1 || checks[0].Status != "fail" {
				t.Fatalf("stale script not reported: %+v", checks)
			}
			if !strings.Contains(checks[0].Message, script) || checks[0].Fix == "" {
				t.Fatalf("report does not name the script or an action: %+v", checks[0])
			}
		})
	}
}

// A directory that does not exist, or holds nothing deploy-shaped, is normal.
func TestDoctorDeployScriptCheckStaysQuietWithoutScripts(t *testing.T) {
	old := deployScriptSearchPaths
	t.Cleanup(func() { deployScriptSearchPaths = old })
	deployScriptSearchPaths = []string{filepath.Join(t.TempDir(), "absent"), t.TempDir()}
	if checks := deployScriptDoctorChecks(); len(checks) != 0 {
		t.Fatalf("unexpected checks: %+v", checks)
	}
}
