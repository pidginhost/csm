package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run the repository's own shell functions through bash with
// fixed test inputs, the same way the existing harness in this package does.
// The deploy and install scripts skipped signature verification whenever the
// .sig download returned 404 and CSM_REQUIRE_SIGNATURES was not 1, for any
// release. Every release since signing began publishes a .sig, so a 404 on
// one of those means the artifact is being served without its signature
// (a mirror, a tampered release page): the skip is only legitimate for a
// release older than signing itself, exactly like the checksum gate.
func runVerifySignatureWithVersion(t *testing.T, script deploySignatureScript, stubs string, env []string, version string) (string, int) {
	t.Helper()
	tmp := t.TempDir()
	payload := filepath.Join(tmp, "csm")
	if err := os.WriteFile(payload, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(repoRootFromDaemonTest(), script.path)
	call := "verify_signature \"$PAYLOAD_FILE\" \"https://example.invalid/csm.sig\""
	if version != "" {
		call += " \"" + version + "\""
	}
	wrapper := filepath.Join(tmp, "run.sh")
	body := strings.Join([]string{
		"#!/bin/bash",
		"set -euo pipefail",
		"die() { echo \"ERROR: $1\" >&2; exit 1; }",
		"info() { echo \"  $1\" >&2; }",
		": \"${CSM_SIGNING_KEY_PEM:=test-key}\"",
		": \"${CSM_REQUIRE_SIGNATURES:=0}\"",
		stubs,
		extractShellFunction(t, scriptPath, "missing_signature_allowed"),
		extractShellFunction(t, scriptPath, "openssl_verifies_ed25519"),
		extractShellFunction(t, scriptPath, "csm_release_verifier"),
		extractShellFunction(t, scriptPath, "verify_signature"),
		call,
		"",
	}, "\n")
	if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", wrapper)
	cmd.Env = withEnv(os.Environ(), append([]string{"PAYLOAD_FILE=" + payload}, env...)...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(out), exitErr.ExitCode()
	}
	t.Fatalf("running bash wrapper failed: %v\n%s", err, out)
	return "", 0
}

func TestVerifySignatureMissingSignatureFailsClosedForSignedReleases(t *testing.T) {
	for _, script := range deploySignatureScripts() {
		t.Run(script.name+"/signed-era", func(t *testing.T) {
			output, code := runVerifySignatureWithVersion(t, script, rawinCapableOpenSSL("404"), nil, "v3.30.0")
			if code == 0 {
				t.Fatalf("a signed-era release without its .sig must fail closed:\n%s", output)
			}
			if !strings.Contains(output, "signature not published") {
				t.Fatalf("expected a missing-signature error, got:\n%s", output)
			}
		})
		t.Run(script.name+"/legacy", func(t *testing.T) {
			output, code := runVerifySignatureWithVersion(t, script, rawinCapableOpenSSL("404"), nil, "v1.0.0")
			if code != 0 {
				t.Fatalf("a release older than signing may skip with a warning, exit %d:\n%s", code, output)
			}
			if !strings.Contains(output, "WARNING") {
				t.Fatalf("expected the legacy skip warning, got:\n%s", output)
			}
		})
		t.Run(script.name+"/unknown-version", func(t *testing.T) {
			output, code := runVerifySignatureWithVersion(t, script, rawinCapableOpenSSL("404"), nil, "")
			if code == 0 {
				t.Fatalf("an unknown release version cannot prove it predates signing:\n%s", output)
			}
		})
	}
}

// Nothing stopped `deploy.sh upgrade` from installing an older release than
// the one running (a stale pinned tag, a rolled-back release page), which
// silently un-fixes everything the newer release carried. A downgrade now
// needs CSM_ALLOW_DOWNGRADE=1.
func runRefuseDowngrade(t *testing.T, scriptPath, current, target string, env []string) (string, int) {
	t.Helper()
	tmp := t.TempDir()
	wrapper := filepath.Join(tmp, "run.sh")
	body := strings.Join([]string{
		"#!/bin/bash",
		"set -euo pipefail",
		"die() { echo \"ERROR: $1\" >&2; exit 1; }",
		": \"${CSM_ALLOW_DOWNGRADE:=0}\"",
		extractShellFunction(t, scriptPath, "version_key"),
		extractShellFunction(t, scriptPath, "refuse_downgrade"),
		"refuse_downgrade \"" + current + "\" \"" + target + "\"",
		"",
	}, "\n")
	if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", wrapper)
	cmd.Env = withEnv(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(out), exitErr.ExitCode()
	}
	t.Fatalf("running bash wrapper failed: %v\n%s", err, out)
	return "", 0
}

func TestRefuseDowngradeGuardsUpgrades(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		path := filepath.Join(root, rel)
		t.Run(rel, func(t *testing.T) {
			if out, code := runRefuseDowngrade(t, path, "csm 3.30.0", "csm 3.29.0", nil); code == 0 || !strings.Contains(out, "downgrade") {
				t.Fatalf("downgrade must be refused by default (exit %d):\n%s", code, out)
			}
			if out, code := runRefuseDowngrade(t, path, "csm 3.30.0", "csm 3.29.0", []string{"CSM_ALLOW_DOWNGRADE=1"}); code != 0 {
				t.Fatalf("CSM_ALLOW_DOWNGRADE=1 must permit the downgrade:\n%s", out)
			}
			if out, code := runRefuseDowngrade(t, path, "csm 3.29.0", "csm 3.30.0", nil); code != 0 {
				t.Fatalf("an upgrade must pass:\n%s", out)
			}
			if out, code := runRefuseDowngrade(t, path, "csm 3.9.0", "csm 3.10.0", nil); code != 0 {
				t.Fatalf("version compare must be numeric, not lexical:\n%s", out)
			}
			if out, code := runRefuseDowngrade(t, path, "unknown", "csm 3.30.0", nil); code != 0 {
				t.Fatalf("an unknown installed version cannot block the upgrade:\n%s", out)
			}
		})
	}
}

func TestUpgradeRefusesDowngradeBeforeStaging(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, rel))
			if err != nil {
				t.Fatal(err)
			}
			body := shellFunctionBody(t, string(data), "do_upgrade")
			guard := strings.Index(body, "refuse_downgrade")
			staging := strings.Index(body, "download_and_stage_assets")
			if guard < 0 || staging < 0 || guard > staging {
				t.Fatalf("%s do_upgrade must refuse a downgrade before staging assets", rel)
			}
		})
	}
}
