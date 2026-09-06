package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Sign with Go and verify through each installed verifier before execution.
func TestCurrentReleaseRequiresAuthenticityBeforeExecution(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := func(key ed25519.PublicKey) string {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	help, _ := exec.Command("openssl", "pkeyutl", "-help").CombinedOutput()
	capable := strings.Contains(string(help), "-rawin")
	// Where OpenSSL cannot verify Ed25519, python3-cryptography does, so an
	// authentic artifact must still verify and run on those hosts.
	pythonCapable := exec.Command("python3", "-I", "-c", "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey").Run() == nil
	payload := []byte("#!/bin/sh\nprintf executed > \"$EXECUTION_MARKER\"\n")
	for _, script := range deploySignatureScripts() {
		for _, tc := range []string{"valid", "tampered", "wrong-key", "missing-signature", "missing-key", "missing-verifier", "old-openssl", "old-openssl-tampered", "old-openssl-wrong-key"} {
			t.Run(script.name+"/"+tc, func(t *testing.T) {
				dir := t.TempDir()
				artifact, signature, marker := filepath.Join(dir, "artifact"), filepath.Join(dir, "signature"), filepath.Join(dir, "executed")
				data := append([]byte(nil), payload...)
				if strings.Contains(tc, "tampered") {
					data = append(data, []byte("# changed\n")...)
				}
				if err := os.WriteFile(artifact, data, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(signature, ed25519.Sign(private, payload), 0600); err != nil {
					t.Fatal(err)
				}
				key := keyPEM(public)
				if strings.Contains(tc, "wrong-key") {
					key = keyPEM(wrong)
				}
				if tc == "missing-key" {
					key = ""
				}
				stubs := `curl() {
 local dest=""
 while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then shift; dest="$1"; fi
  shift
 done
 /bin/cp "$SOURCE_SIGNATURE" "$dest"
 printf 200
}
pkg_download() { /bin/cp "$SOURCE_SIGNATURE" "$2"; printf 200; }`
				if tc == "missing-signature" {
					stubs = `curl() { printf 404; }; pkg_download() { printf 404; }`
				}
				if strings.HasPrefix(tc, "old-openssl") {
					stubs += "\n" + oldOpenSSL()
				}
				wrapper := strings.Join([]string{
					"set -euo pipefail",
					`die() { printf '%s\n' "$1" >&2; exit 1; }`,
					`info() { printf '%s\n' "$1" >&2; }`,
					"CSM_REQUIRE_SIGNATURES=0",
					stubs,
					extractShellFunction(t, filepath.Join(repoRootFromDaemonTest(), script.path), "missing_signature_allowed"),
					extractShellFunction(t, filepath.Join(repoRootFromDaemonTest(), script.path), "openssl_verifies_ed25519"),
					extractShellFunction(t, filepath.Join(repoRootFromDaemonTest(), script.path), "csm_release_verifier"),
					extractShellFunction(t, filepath.Join(repoRootFromDaemonTest(), script.path), "python_verifies_ed25519"),
					extractShellFunction(t, filepath.Join(repoRootFromDaemonTest(), script.path), "verify_with_python"),
					extractShellFunction(t, filepath.Join(repoRootFromDaemonTest(), script.path), "verify_signature"),
					`verify_signature "$PAYLOAD_FILE" https://example.invalid/current.sig v3.33.1`,
					`"$PAYLOAD_FILE"`,
				}, "\n")
				command := exec.Command("/bin/bash", "-c", wrapper)
				command.Env = withEnv(os.Environ(), "CSM_SIGNING_KEY_PEM="+key, "SOURCE_SIGNATURE="+signature, "PAYLOAD_FILE="+artifact, "EXECUTION_MARKER="+marker)
				if tc == "missing-verifier" {
					command.Env = withEnv(command.Env, "PATH="+dir)
				}
				output, runErr := command.CombinedOutput()
				wantPass := (tc == "valid" && (capable || pythonCapable)) || (tc == "old-openssl" && pythonCapable)
				if (runErr == nil) != wantPass {
					t.Fatalf("capable=%v error=%v output=%s", capable, runErr, output)
				}
				recorded, readErr := os.ReadFile(marker)
				if wantPass {
					if readErr != nil || string(recorded) != "executed" || !strings.Contains(string(output), "Signature verified OK") {
						t.Fatalf("verified artifact did not execute: %q %v %s", recorded, readErr, output)
					}
				} else if !os.IsNotExist(readErr) {
					t.Fatalf("unverified artifact executed: %q %v", recorded, readErr)
				}
			})
		}
	}
}

func TestLegacySignatureExceptionRequiresCompletePreSigningVersion(t *testing.T) {
	for _, script := range deploySignatureScripts() {
		for _, version := range []string{"v1.0.0", "v2.1.9", "v2.2.0", "v2.1.9-suffix", "v1.0.0/current", "v01.0.0", "latest", ""} {
			t.Run(script.name+"/"+version, func(t *testing.T) {
				stubs := rawinCapableOpenSSL("404") + oldOpenSSL() + "\nCSM_SIGNING_KEY_PEM=''\n"
				output, code := runVerifySignatureWithVersion(t, script, stubs, nil, version)
				legacy := version == "v1.0.0" || version == "v2.1.9"
				// The internal registry signs tagged releases only, so an
				// unsigned CI build is expected there and nowhere else.
				ciBuild := version == "latest" && script.path == "scripts/deploy-gitlab.sh"
				allowed := legacy || ciBuild
				if (code == 0) != allowed {
					t.Fatalf("version=%q exit=%d output=%s", version, code, output)
				}
				if legacy && !strings.Contains(output, "pre-signing release") {
					t.Fatalf("legacy bypass not disclosed: %s", output)
				}
				if ciBuild && !strings.Contains(output, "unsigned CI build") {
					t.Fatalf("CI build acceptance not disclosed: %s", output)
				}
				if allowed {
					strictOut, strictCode := runVerifySignatureWithVersion(t, script, stubs, []string{"CSM_REQUIRE_SIGNATURES=1"}, version)
					if strictCode == 0 {
						t.Fatalf("strict legacy accepted: %s", strictOut)
					}
				}
			})
		}
	}
}

func TestGitLabUpdateCheckNeverExecutesDownloadedCode(t *testing.T) {
	dir := t.TempDir()
	installed, unsigned, marker, requests := filepath.Join(dir, "csm"), filepath.Join(dir, "unsigned"), filepath.Join(dir, "executed"), filepath.Join(dir, "requests")
	if err := os.WriteFile(installed, []byte("#!/bin/sh\nprintf 'csm 1.0.0\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unsigned, []byte("#!/bin/sh\nprintf executed > \"$EXECUTION_MARKER\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	body := strings.Join([]string{
		"set -euo pipefail",
		"detect_auth_header() { :; }",
		`sha256sum() { printf '%064d\n' 1; }`,
		"PKG_BASE=https://example.invalid/pkg",
		"ARTIFACT_NAME=artifact",
		`pkg_download() {
 printf '%s\n' "$1" >> "$REQUESTS"
 case "$1" in
  *.sha256) printf '%064d\n' 0 > "$2";;
  *) cp "$UNSIGNED" "$2";;
 esac
 printf 200
}`,
		extractShellFunction(t, filepath.Join(repoRootFromDaemonTest(), "scripts/deploy-gitlab.sh"), "do_check"),
		"do_check",
	}, "\n")
	cmd := exec.Command("/bin/bash", "-c", body)
	cmd.Env = withEnv(os.Environ(), "INSTALL_DIR="+dir, "BINARY_PATH="+installed, "UNSIGNED="+unsigned, "EXECUTION_MARKER="+marker, "REQUESTS="+requests)
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "Update available") {
		t.Fatalf("update check: %v %s", err, output)
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Errorf("update check executed downloaded code: %v", err)
	}
	got, err := os.ReadFile(requests)
	if err != nil || string(got) != "https://example.invalid/pkg/latest/artifact.sha256\n" {
		t.Fatalf("update check downloaded executable content: %s %v", got, err)
	}
}
