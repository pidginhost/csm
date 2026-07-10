package daemon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type deploySignatureScript struct {
	name string
	path string
}

func TestDeployScriptEmbeddedCopyMatches(t *testing.T) {
	root := repoRootFromDaemonTest()
	canonical, err := os.ReadFile(filepath.Join(root, "scripts/deploy.sh"))
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := os.ReadFile(filepath.Join(root, "internal/daemon/configs/deploy.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, embedded) {
		t.Fatal("internal/daemon/configs/deploy.sh must match scripts/deploy.sh byte-for-byte")
	}
}

func TestVerifySignatureRejectsMismatchWhenRawinSupported(t *testing.T) {
	for _, script := range deploySignatureScripts() {
		t.Run(script.name, func(t *testing.T) {
			output, code := runVerifySignature(t, script, rawinCapableOpenSSL("200"), nil, "")
			if code == 0 {
				t.Fatalf("verify_signature succeeded on mismatched signature output:\n%s", output)
			}
			if !strings.Contains(output, "SIGNATURE VERIFICATION FAILED") {
				t.Fatalf("expected signature mismatch failure, got:\n%s", output)
			}
			if strings.Contains(output, "skipping signature") {
				t.Fatalf("rawin-capable OpenSSL must not take skip path:\n%s", output)
			}
		})
	}
}

func TestVerifySignatureSkipsOldOpenSSLOnlyWhenNotStrict(t *testing.T) {
	for _, script := range deploySignatureScripts() {
		t.Run(script.name, func(t *testing.T) {
			output, code := runVerifySignature(t, script, oldOpenSSL(), nil, "")
			if code != 0 {
				t.Fatalf("old OpenSSL should warn and continue when signatures are not required, exit %d:\n%s", code, output)
			}
			if !strings.Contains(output, "openssl too old for Ed25519 verification") {
				t.Fatalf("expected old OpenSSL warning, got:\n%s", output)
			}

			output, code = runVerifySignature(t, script, oldOpenSSL(), []string{"CSM_REQUIRE_SIGNATURES=1"}, "")
			if code == 0 {
				t.Fatalf("strict mode should reject old OpenSSL:\n%s", output)
			}
			if !strings.Contains(output, "CSM_REQUIRE_SIGNATURES=1") {
				t.Fatalf("expected strict-mode error, got:\n%s", output)
			}
		})
	}
}

func TestVerifySignatureFailsClosedWhenStrict(t *testing.T) {
	for _, script := range deploySignatureScripts() {
		t.Run(script.name+"/missing-openssl", func(t *testing.T) {
			output, code := runVerifySignature(t, script, noDownloader(), []string{"CSM_REQUIRE_SIGNATURES=1"}, t.TempDir())
			if code == 0 {
				t.Fatalf("strict mode should reject missing openssl:\n%s", output)
			}
			if !strings.Contains(output, "openssl is not installed") {
				t.Fatalf("expected missing openssl error, got:\n%s", output)
			}
		})

		t.Run(script.name+"/signature-404", func(t *testing.T) {
			output, code := runVerifySignature(t, script, rawinCapableOpenSSL("404"), []string{"CSM_REQUIRE_SIGNATURES=1"}, "")
			if code == 0 {
				t.Fatalf("strict mode should reject missing signature asset:\n%s", output)
			}
			if !strings.Contains(output, "Signature download failed (HTTP 404)") {
				t.Fatalf("expected signature download failure, got:\n%s", output)
			}
		})
	}
}

func TestReleaseInstallScriptsVerifyAssetsBeforeExtraction(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/install.sh", "scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, rel))
			if err != nil {
				t.Fatal(err)
			}
			body := string(data)
			for _, want := range []string{
				"assets.tar.gz.sha256",
				"verify_signature",
				"validate_assets_archive",
			} {
				if !strings.Contains(body, want) {
					t.Errorf("%s missing verified asset install step %q", rel, want)
				}
			}
			if strings.Contains(body, `tar xzf "${tmpdir}/csm-assets.tar.gz" -C "$INSTALL_DIR" 2>/dev/null || true`) {
				t.Errorf("%s still ignores asset extraction failures", rel)
			}
		})
	}
}

func TestValidateAssetsArchiveRejectsTraversalAndLinks(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/install.sh", "scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			script := filepath.Join(root, rel)
			t.Run("regular-files", func(t *testing.T) {
				archive := writeAssetsArchive(t, []tar.Header{
					{Name: "ui/", Typeflag: tar.TypeDir, Mode: 0o755},
					{Name: "ui/index.html", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2},
				})
				output, code := runValidateAssetsArchive(t, script, archive)
				if code != 0 {
					t.Fatalf("safe archive rejected, exit %d:\n%s", code, output)
				}
			})

			t.Run("traversal", func(t *testing.T) {
				archive := writeAssetsArchive(t, []tar.Header{{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644}})
				output, code := runValidateAssetsArchive(t, script, archive)
				if code == 0 || !strings.Contains(output, "Unsafe path") {
					t.Fatalf("traversal archive accepted, exit %d:\n%s", code, output)
				}
			})

			t.Run("symlink", func(t *testing.T) {
				archive := writeAssetsArchive(t, []tar.Header{{
					Name: "ui/outside", Typeflag: tar.TypeSymlink, Linkname: "/etc", Mode: 0o777,
				}})
				output, code := runValidateAssetsArchive(t, script, archive)
				if code == 0 || !strings.Contains(output, "link or special file") {
					t.Fatalf("symlink archive accepted, exit %d:\n%s", code, output)
				}
			})
		})
	}
}

func TestDeployInstallAndUpgradeKeepAssetsTransactional(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, rel))
			if err != nil {
				t.Fatal(err)
			}
			body := string(data)
			installBody := shellFunctionBody(t, body, "do_install")
			for _, want := range []string{"download_and_stage_assets", "activate_assets"} {
				if !strings.Contains(installBody, want) {
					t.Errorf("%s do_install missing %s", rel, want)
				}
			}

			upgradeBody := shellFunctionBody(t, body, "do_upgrade")
			start := strings.Index(upgradeBody, "start_services")
			cleanup := strings.Index(upgradeBody, "cleanup_upgrade_backup")
			if start < 0 || cleanup < 0 || cleanup < start {
				t.Errorf("%s must keep rollback material until start_services succeeds", rel)
			}
			if strings.Count(upgradeBody, `if ! "$BINARY_PATH" rehash`) != 1 {
				t.Errorf("%s must have exactly one primary upgrade rehash", rel)
			}
		})
	}
}

func TestDeployAssetActivationRollbackRestoresPreviousRelease(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			installDir := t.TempDir()
			stage := t.TempDir()
			backup := filepath.Join(t.TempDir(), "backup")

			for _, entry := range []string{"ui", "configs", "pam"} {
				writeDeployTestFile(t, filepath.Join(installDir, entry, "release"), "old")
				writeDeployTestFile(t, filepath.Join(stage, entry, "release"), "new")
			}
			writeDeployTestFile(t, filepath.Join(installDir, "deploy.sh"), "old")
			writeDeployTestFile(t, filepath.Join(stage, "deploy.sh"), "new")
			for _, rule := range []string{"malware.yml", "malware.yar"} {
				writeDeployTestFile(t, filepath.Join(installDir, "rules", rule), "old")
				writeDeployTestFile(t, filepath.Join(stage, "configs", rule), "new")
			}

			script := filepath.Join(root, rel)
			wrapper := filepath.Join(t.TempDir(), "asset-rollback.sh")
			body := strings.Join([]string{
				"#!/bin/bash",
				"set -euo pipefail",
				extractShellFunction(t, script, "activate_assets"),
				extractShellFunction(t, script, "rollback_assets"),
				"activate_assets \"$TEST_STAGE\" \"$TEST_BACKUP\"",
				"rollback_assets \"$TEST_BACKUP\"",
				"",
			}, "\n")
			if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/bash", wrapper)
			cmd.Env = append(os.Environ(),
				"INSTALL_DIR="+installDir,
				"TEST_STAGE="+stage,
				"TEST_BACKUP="+backup,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("asset activation and rollback: %v\n%s", err, out)
			}

			for _, path := range []string{
				filepath.Join(installDir, "ui", "release"),
				filepath.Join(installDir, "configs", "release"),
				filepath.Join(installDir, "pam", "release"),
				filepath.Join(installDir, "deploy.sh"),
				filepath.Join(installDir, "rules", "malware.yml"),
				filepath.Join(installDir, "rules", "malware.yar"),
			} {
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != "old" {
					t.Errorf("%s = %q after rollback, want old", path, got)
				}
			}
		})
	}
}

func TestInstallInstructionsStartDaemonBeforeBaseline(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{
		"scripts/install.sh",
		"scripts/deploy.sh",
		"scripts/deploy-gitlab.sh",
		"build/packaging/scripts/postinstall.sh",
		"cmd/csm/installer.go",
	} {
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, rel))
			if err != nil {
				t.Fatal(err)
			}
			body := string(data)
			start := strings.LastIndex(body, "systemctl enable --now csm.service")
			baseline := strings.LastIndex(body, "baseline")
			if start < 0 || baseline < 0 || start > baseline {
				t.Errorf("%s must tell operators to start csm.service before baseline", rel)
			}
		})
	}
}

func TestInstallHooksRespectConfiguredBinaryImmutability(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{
		"build/packaging/scripts/postinstall.sh",
		"scripts/install.sh",
	} {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "chattr +i") {
			t.Errorf("%s must not override integrity.immutable=false", rel)
		}
	}

	posttrans, err := os.ReadFile(filepath.Join(root, "build/packaging/scripts/posttrans.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(posttrans), "/opt/csm/csm config apply-immutability") {
		t.Fatal("posttrans must restore the configured immutable state")
	}
}

func deploySignatureScripts() []deploySignatureScript {
	return []deploySignatureScript{
		{name: "scripts-deploy", path: "scripts/deploy.sh"},
		{name: "embedded-deploy", path: "internal/daemon/configs/deploy.sh"},
		{name: "scripts-install", path: "scripts/install.sh"},
		{name: "scripts-deploy-gitlab", path: "scripts/deploy-gitlab.sh"},
	}
}

func runVerifySignature(t *testing.T, script deploySignatureScript, stubs string, env []string, pathOverride string) (string, int) {
	t.Helper()

	tmp := t.TempDir()
	payload := filepath.Join(tmp, "csm")
	if err := os.WriteFile(payload, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
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
		extractShellFunction(t, filepath.Join(repoRootFromDaemonTest(), script.path), "verify_signature"),
		"verify_signature \"$PAYLOAD_FILE\" \"https://example.invalid/csm.sig\"",
		"",
	}, "\n")
	if err := os.WriteFile(wrapper, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("/bin/bash", wrapper)
	cmd.Env = withEnv(os.Environ(), append([]string{"PAYLOAD_FILE=" + payload}, env...)...)
	if pathOverride != "" {
		cmd.Env = withEnv(cmd.Env, "PATH="+pathOverride)
	}
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

func withEnv(base []string, overrides ...string) []string {
	out := append([]string(nil), base...)
	for _, override := range overrides {
		key, _, ok := strings.Cut(override, "=")
		if !ok {
			continue
		}
		replaced := false
		prefix := key + "="
		for i, existing := range out {
			if strings.HasPrefix(existing, prefix) {
				out[i] = override
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, override)
		}
	}
	return out
}

func extractShellFunction(t *testing.T, path, name string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	start := strings.Index(text, name+"() {")
	if start < 0 {
		t.Fatalf("%s not found in %s", name, path)
	}
	lines := strings.Split(text[start:], "\n")
	depth := 0
	for i, line := range lines {
		depth += strings.Count(line, "{")
		depth -= strings.Count(line, "}")
		if i > 0 && depth == 0 {
			return strings.Join(lines[:i+1], "\n")
		}
	}
	t.Fatalf("%s body did not close in %s", name, path)
	return ""
}

func shellFunctionBody(t *testing.T, script, name string) string {
	t.Helper()
	start := strings.Index(script, name+"() {")
	if start < 0 {
		t.Fatalf("%s not found", name)
	}
	lines := strings.Split(script[start:], "\n")
	depth := 0
	for i, line := range lines {
		depth += strings.Count(line, "{")
		depth -= strings.Count(line, "}")
		if i > 0 && depth == 0 {
			return strings.Join(lines[:i+1], "\n")
		}
	}
	t.Fatalf("%s body did not close", name)
	return ""
}

func runValidateAssetsArchive(t *testing.T, script, archive string) (string, int) {
	t.Helper()
	wrapper := filepath.Join(t.TempDir(), "validate-assets.sh")
	body := strings.Join([]string{
		"#!/bin/bash",
		"set -euo pipefail",
		"die() { echo \"ERROR: $1\" >&2; exit 1; }",
		extractShellFunction(t, script, "validate_assets_archive"),
		"validate_assets_archive \"$ASSET_ARCHIVE\"",
		"",
	}, "\n")
	if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", wrapper)
	cmd.Env = withEnv(os.Environ(), "ASSET_ARCHIVE="+archive)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(out), exitErr.ExitCode()
	}
	t.Fatalf("running archive validator failed: %v\n%s", err, out)
	return "", 0
}

func writeAssetsArchive(t *testing.T, headers []tar.Header) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "assets.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for i := range headers {
		h := headers[i]
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg && h.Size > 0 {
			if _, err := tw.Write(bytes.Repeat([]byte{'x'}, int(h.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeDeployTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rawinCapableOpenSSL(httpStatus string) string {
	return `
openssl() {
    if [ "$1" = "pkeyutl" ] && [ "${2:-}" = "-help" ]; then
        printf '%s\n' 'Usage: pkeyutl' ' -rawin raw input'
        i=0
        while [ "$i" -lt 20000 ]; do
            printf '%s\n' "tail $i"
            i=$((i + 1))
        done
        return 0
    fi
    if [ "$1" = "version" ]; then
        printf '%s\n' 'OpenSSL 3.0.0'
        return 0
    fi
    if [ "$1" = "pkeyutl" ]; then
        return 1
    fi
    return 2
}

curl() {
    local out=''
    while [ "$#" -gt 0 ]; do
        if [ "$1" = "-o" ]; then
            out="$2"
            shift 2
            continue
        fi
        shift
    done
    if [ -n "$out" ]; then
        printf '%s' 'bad signature' > "$out"
    fi
    printf '%s' '` + httpStatus + `'
}

pkg_download() {
    printf '%s' 'bad signature' > "$2"
    printf '%s' '` + httpStatus + `'
}
`
}

func oldOpenSSL() string {
	return `
openssl() {
    if [ "$1" = "pkeyutl" ] && [ "${2:-}" = "-help" ]; then
        printf '%s\n' 'Usage: pkeyutl' ' -verify verify with public key'
        return 0
    fi
    if [ "$1" = "version" ]; then
        printf '%s\n' 'OpenSSL 1.1.1k'
        return 0
    fi
    return 2
}
` + noDownloader()
}

func noDownloader() string {
	return `
curl() {
    echo 'curl should not be called' >&2
    return 99
}

pkg_download() {
    echo 'pkg_download should not be called' >&2
    return 99
}
`
}

func repoRootFromDaemonTest() string {
	return filepath.Clean(filepath.Join("..", ".."))
}
