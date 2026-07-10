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

func TestVerifySignatureSuccessDoesNotAbortEnclosingFunction(t *testing.T) {
	for _, script := range deploySignatureScripts() {
		t.Run(script.name, func(t *testing.T) {
			tmp := t.TempDir()
			payload := filepath.Join(tmp, "csm")
			keyFile := filepath.Join(tmp, "signing-key.pem")
			if err := os.WriteFile(payload, []byte("payload"), 0o600); err != nil {
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
				verifyingOpenSSL(),
				extractShellFunction(t, filepath.Join(repoRootFromDaemonTest(), script.path), "verify_signature"),
				"stage_assets() {",
				"    verify_signature \"$PAYLOAD_FILE\" \"https://example.invalid/csm.sig\"",
				"    echo \"${PAYLOAD_FILE}.stage\"",
				"}",
				"stage=$(stage_assets)",
				"[ \"$stage\" = \"${PAYLOAD_FILE}.stage\" ] || die \"stage path corrupted: ${stage}\"",
				"echo VERIFY_WRAPPER_OK",
				"",
			}, "\n")
			if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command("/bin/bash", wrapper)
			cmd.Env = withEnv(os.Environ(), "PAYLOAD_FILE="+payload, "KEY_FILE="+keyFile)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("verified artifact must not abort the calling function: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), "VERIFY_WRAPPER_OK") {
				t.Fatalf("wrapper did not complete after verification:\n%s", out)
			}
			for _, path := range []string{keyFile, payload + ".sig"} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Errorf("temporary verification file was not removed: %s", path)
				}
			}
		})
	}
}

func TestAssetsChecksumMissingToleratedUnlessStrict(t *testing.T) {
	root := repoRootFromDaemonTest()
	fixture := writeAssetsArchive(t, []tar.Header{
		{Name: "ui/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "ui/index.html", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2},
		{Name: "configs/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "pam/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "deploy.sh", Typeflag: tar.TypeReg, Mode: 0o755, Size: 2},
	})

	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			script := filepath.Join(root, rel)
			run := func(env ...string) (string, int) {
				wrapper := filepath.Join(t.TempDir(), "stage-assets.sh")
				body := strings.Join([]string{
					"#!/bin/bash",
					"set -euo pipefail",
					"die() { echo \"ERROR: $1\" >&2; exit 1; }",
					": \"${CSM_REQUIRE_SIGNATURES:=0}\"",
					": \"${RELEASE_VERSION:=3.23.1}\"",
					"export RELEASE_VERSION",
					"ARTIFACT_NAME='csm-linux-amd64'",
					"PKG_BASE='https://example.invalid/pkg'",
					extractShellFunction(t, script, "verify_checksum"),
					extractShellFunction(t, script, "missing_assets_checksum_allowed"),
					extractShellFunction(t, script, "validate_assets_archive"),
					extractShellFunction(t, script, "download_and_stage_assets"),
					"get_download_url() { printf 'https://example.invalid/%s\\n' \"$1\"; }",
					"curl() {",
					"    local out='' url=''",
					"    while [ \"$#\" -gt 0 ]; do",
					"        if [ \"$1\" = '-o' ]; then out=\"$2\"; shift 2; continue; fi",
					"        url=\"$1\"; shift",
					"    done",
					"    case \"$url\" in",
					"        *.sha256) printf '404' ;;",
					"        *) cp \"$ASSET_FIXTURE\" \"$out\"; printf '200' ;;",
					"    esac",
					"}",
					"pkg_download() {",
					"    case \"$1\" in",
					"        *.sha256) printf '404' ;;",
					"        *) cp \"$ASSET_FIXTURE\" \"$2\"; printf '200' ;;",
					"    esac",
					"}",
					"verify_signature() { :; }",
					"printf '%s\\n' '#!/bin/bash' 'printf \"csm %s (build: test, date: test)\\n\" \"$RELEASE_VERSION\"' > \"${WORK_DIR}/${ARTIFACT_NAME}\"",
					"chmod +x \"${WORK_DIR}/${ARTIFACT_NAME}\"",
					"stage=$(download_and_stage_assets latest \"$WORK_DIR\")",
					"[ -d \"${stage}/ui\" ] || die \"stage missing ui: ${stage}\"",
					"echo STAGE_OK",
					"",
				}, "\n")
				if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("/bin/bash", wrapper)
				cmd.Env = withEnv(os.Environ(), append([]string{
					"ASSET_FIXTURE=" + fixture,
					"WORK_DIR=" + t.TempDir(),
					"CSM_REQUIRE_SIGNATURES=0",
					"RELEASE_VERSION=3.23.1",
				}, env...)...)
				out, err := cmd.CombinedOutput()
				if err == nil {
					return string(out), 0
				}
				if exitErr, ok := err.(*exec.ExitError); ok {
					return string(out), exitErr.ExitCode()
				}
				t.Fatalf("running staging wrapper failed: %v\n%s", err, out)
				return "", 0
			}

			output, code := run()
			if code != 0 {
				t.Fatalf("missing checksum must not fail against releases published before checksums existed, exit %d:\n%s", code, output)
			}
			if !strings.Contains(output, "STAGE_OK") {
				t.Fatalf("staging did not complete:\n%s", output)
			}
			if !strings.Contains(output, "skipping checksum") {
				t.Fatalf("expected checksum-skip warning:\n%s", output)
			}

			output, code = run("CSM_REQUIRE_SIGNATURES=1")
			if code == 0 {
				t.Fatalf("strict mode must reject a missing assets checksum:\n%s", output)
			}

			output, code = run("RELEASE_VERSION=3.24.0")
			if code == 0 {
				t.Fatalf("a release that should publish an assets checksum must reject a missing one:\n%s", output)
			}
		})
	}

	// install.sh verifies assets inline rather than via download_and_stage_assets.
	body, err := os.ReadFile(filepath.Join(root, "scripts/install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`RELEASE_VERSION=$(printf '%s\n' "$VERSION" | awk '{print $2}')`,
		`missing_assets_checksum_allowed "$RELEASE_VERSION"`,
		`rm -f "${TMPDIR}/assets.tar.gz.sha256"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("scripts/install.sh missing legacy-checksum handling %q", want)
		}
	}
}

func TestMissingAssetsChecksumAllowedOnlyForLegacyReleases(t *testing.T) {
	tests := []struct {
		version string
		allowed bool
	}{
		{version: "2.12.0", allowed: true},
		{version: "3.23.0", allowed: true},
		{version: "3.23.1", allowed: true},
		{version: "v3.23.1", allowed: true},
		{version: "3.23.2", allowed: false},
		{version: "3.24.0", allowed: false},
		{version: "4.0.0", allowed: false},
		{version: "3.23.1-5-gabcdef0", allowed: false},
		{version: "dev", allowed: false},
	}

	root := repoRootFromDaemonTest()
	for _, script := range deploySignatureScripts() {
		t.Run(script.name, func(t *testing.T) {
			function := extractShellFunction(t, filepath.Join(root, script.path), "missing_assets_checksum_allowed")
			for _, test := range tests {
				t.Run(test.version, func(t *testing.T) {
					wrapper := filepath.Join(t.TempDir(), "legacy-checksum.sh")
					body := strings.Join([]string{
						"#!/bin/bash",
						"set -euo pipefail",
						function,
						"missing_assets_checksum_allowed \"$RELEASE_VERSION\"",
						"",
					}, "\n")
					if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command("/bin/bash", wrapper)
					cmd.Env = withEnv(os.Environ(), "RELEASE_VERSION="+test.version)
					err := cmd.Run()
					if (err == nil) != test.allowed {
						t.Fatalf("missing checksum allowed=%t, want %t (error: %v)", err == nil, test.allowed, err)
					}
				})
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

			t.Run("bare-parent-dir", func(t *testing.T) {
				archive := writeAssetsArchive(t, []tar.Header{{Name: "..", Typeflag: tar.TypeDir, Mode: 0o777}})
				output, code := runValidateAssetsArchive(t, script, archive)
				if code == 0 || !strings.Contains(output, "Unsafe path") {
					t.Fatalf("bare .. entry accepted, exit %d:\n%s", code, output)
				}
			})

			t.Run("dot-slash-parent-dir", func(t *testing.T) {
				archive := writeAssetsArchive(t, []tar.Header{{Name: "./..", Typeflag: tar.TypeDir, Mode: 0o777}})
				output, code := runValidateAssetsArchive(t, script, archive)
				if code == 0 || !strings.Contains(output, "Unsafe path") {
					t.Fatalf("./.. entry accepted, exit %d:\n%s", code, output)
				}
			})

			t.Run("corrupt-archive", func(t *testing.T) {
				archive := writeAssetsArchive(t, []tar.Header{
					{Name: "ui/", Typeflag: tar.TypeDir, Mode: 0o755},
					{Name: "ui/index.html", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2},
				})
				data, err := os.ReadFile(archive)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(archive, data[:len(data)/2], 0o600); err != nil {
					t.Fatal(err)
				}
				output, code := runValidateAssetsArchive(t, script, archive)
				if code == 0 {
					t.Fatalf("corrupt archive passed validation:\n%s", output)
				}
			})
		})
	}
}

func TestAssetExtractionFailuresAreFatal(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		stageBody := shellFunctionBody(t, string(body), "download_and_stage_assets")
		if !strings.Contains(stageBody, `--no-same-permissions || die`) {
			t.Errorf("%s download_and_stage_assets must die when tar extraction fails", rel)
		}
	}

	installBody, err := os.ReadFile(filepath.Join(root, "scripts/install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installBody), `--no-same-permissions || die`) {
		t.Error("scripts/install.sh must die when tar extraction fails")
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
				"rollback_assets \"$TEST_STAGE\" \"$TEST_BACKUP\"",
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

func TestRollbackAssetsRemovesRulesCreatedByFailedRelease(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			installDir := t.TempDir()
			stage := t.TempDir()
			backup := filepath.Join(t.TempDir(), "backup")

			for _, entry := range []string{"ui", "configs", "pam"} {
				writeDeployTestFile(t, filepath.Join(stage, entry, "release"), "new")
			}
			writeDeployTestFile(t, filepath.Join(stage, "deploy.sh"), "new")
			for _, rule := range []string{"malware.yml", "malware.yar"} {
				writeDeployTestFile(t, filepath.Join(stage, "configs", rule), "new")
			}

			script := filepath.Join(root, rel)
			wrapper := filepath.Join(t.TempDir(), "asset-rollback-new-rules.sh")
			body := strings.Join([]string{
				"#!/bin/bash",
				"set -euo pipefail",
				extractShellFunction(t, script, "activate_assets"),
				extractShellFunction(t, script, "rollback_assets"),
				"activate_assets \"$TEST_STAGE\" \"$TEST_BACKUP\"",
				"rollback_assets \"$TEST_STAGE\" \"$TEST_BACKUP\"",
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

			for _, rule := range []string{"malware.yml", "malware.yar"} {
				path := filepath.Join(installDir, "rules", rule)
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Errorf("new rule survived failed release rollback: %s (error: %v)", path, err)
				}
			}
		})
	}
}

func TestRollbackAssetsPreservesEntriesNeverActivated(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			installDir := t.TempDir()
			stage := t.TempDir()
			backup := filepath.Join(t.TempDir(), "backup")
			if err := os.MkdirAll(backup, 0o700); err != nil {
				t.Fatal(err)
			}

			// Activation failed before touching anything: the live entries are
			// still in place, the stage still holds every new entry, and the
			// backup is empty. Rollback must leave the live entries alone.
			for _, entry := range []string{"ui", "configs", "pam"} {
				writeDeployTestFile(t, filepath.Join(installDir, entry, "release"), "old")
				writeDeployTestFile(t, filepath.Join(stage, entry, "release"), "new")
			}
			writeDeployTestFile(t, filepath.Join(installDir, "deploy.sh"), "old")
			writeDeployTestFile(t, filepath.Join(stage, "deploy.sh"), "new")
			writeDeployTestFile(t, filepath.Join(installDir, "rules", "malware.yml"), "old")
			writeDeployTestFile(t, filepath.Join(installDir, "rules", "malware.yar"), "old")

			script := filepath.Join(root, rel)
			wrapper := filepath.Join(t.TempDir(), "asset-rollback-noop.sh")
			body := strings.Join([]string{
				"#!/bin/bash",
				"set -euo pipefail",
				extractShellFunction(t, script, "rollback_assets"),
				"rollback_assets \"$TEST_STAGE\" \"$TEST_BACKUP\"",
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
				t.Fatalf("rollback after failed activation: %v\n%s", err, out)
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
					t.Fatalf("rollback destroyed a live entry it never backed up: %v", err)
				}
				if string(got) != "old" {
					t.Errorf("%s = %q after rollback, want untouched old content", path, got)
				}
			}
		})
	}
}

func TestRollbackAssetsContinuesPastFailures(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			installDir := t.TempDir()
			stage := t.TempDir()
			backup := filepath.Join(t.TempDir(), "backup")

			// ui: removal is forced to fail, stage entry is gone, and backup is
			// ready. configs afterwards must still be restored, and the old ui
			// backup must not be nested inside the live directory by mv.
			writeDeployTestFile(t, filepath.Join(installDir, "ui", "release"), "new")
			writeDeployTestFile(t, filepath.Join(backup, "ui", "release"), "old")

			writeDeployTestFile(t, filepath.Join(installDir, "configs", "release"), "new")
			writeDeployTestFile(t, filepath.Join(backup, "configs", "release"), "old")

			script := filepath.Join(root, rel)
			wrapper := filepath.Join(t.TempDir(), "asset-rollback-tolerant.sh")
			body := strings.Join([]string{
				"#!/bin/bash",
				"set -euo pipefail",
				"rm() {",
				"    if [ \"${!#}\" = \"${INSTALL_DIR}/ui\" ]; then return 1; fi",
				"    command rm \"$@\"",
				"}",
				extractShellFunction(t, script, "rollback_assets"),
				"rollback_status=0",
				"rollback_assets \"$TEST_STAGE\" \"$TEST_BACKUP\" || rollback_status=$?",
				"[ \"$rollback_status\" -ne 0 ]",
				"echo ROLLBACK_COMPLETED",
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
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("rollback aborted on a failing step instead of continuing: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), "ROLLBACK_COMPLETED") {
				t.Fatalf("rollback did not run to completion:\n%s", out)
			}

			got, err := os.ReadFile(filepath.Join(installDir, "configs", "release"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "old" {
				t.Errorf("configs = %q after rollback, want old restored despite earlier failure", got)
			}
			if _, statErr := os.Stat(filepath.Join(installDir, "ui", "ui", "release")); !os.IsNotExist(statErr) {
				t.Errorf("ui backup was nested into the live directory after removal failed (error: %v)", statErr)
			}
			got, err = os.ReadFile(filepath.Join(backup, "ui", "release"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "old" {
				t.Errorf("ui backup = %q after failed restore, want preserved old content", got)
			}
		})
	}
}

func TestRollbackUpgradeRestoresImmutableState(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			script := filepath.Join(root, rel)
			upgradeBody, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(shellFunctionBody(t, string(upgradeBody), "do_upgrade"), "binary_was_immutable") {
				t.Error("do_upgrade must capture the binary's immutable state before clearing it")
			}

			run := func(wasImmutable string) (string, string) {
				dir := t.TempDir()
				capture := filepath.Join(dir, "chattr-args")
				binary := filepath.Join(dir, "csm")
				fakeBinary := strings.Join([]string{
					"#!/bin/bash",
					"printf '%s\\n' \"+i $0\" >> \"$CHATTR_CAPTURE\"",
					"",
				}, "\n")
				if err := os.WriteFile(binary, []byte(fakeBinary), 0o700); err != nil {
					t.Fatal(err)
				}
				wrapper := filepath.Join(dir, "rollback-upgrade.sh")
				body := strings.Join([]string{
					"#!/bin/bash",
					"set -uo pipefail",
					"die() { echo \"ERROR: $1\" >&2; exit 1; }",
					"chattr() { printf '%s\\n' \"$*\" >> \"$CHATTR_CAPTURE\"; }",
					"lsattr() { :; }",
					"cp() { :; }",
					"start_services() { :; }",
					"rollback_assets() { :; }",
					extractShellFunction(t, script, "rollback_upgrade"),
					"BINARY_PATH=\"$TEST_BINARY\"",
					"binary_backup=\"$TEST_BINARY\"",
					"assets_stage=/tmp",
					"asset_backup=/tmp",
					"binary_was_immutable=" + wasImmutable,
					"rollback_upgrade 'Test failure'",
					"",
				}, "\n")
				if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("/bin/bash", wrapper)
				cmd.Env = withEnv(os.Environ(), "CHATTR_CAPTURE="+capture, "TEST_BINARY="+binary)
				out, runErr := cmd.CombinedOutput()
				calls := ""
				if data, readErr := os.ReadFile(capture); readErr == nil {
					calls = string(data)
				}
				if runErr == nil {
					t.Fatalf("rollback_upgrade must die, but exited 0:\n%s", out)
				}
				return calls, binary
			}

			lastCall := func(calls string) string {
				lines := strings.Split(strings.TrimSpace(calls), "\n")
				return lines[len(lines)-1]
			}

			calls, binary := run("1")
			if got := lastCall(calls); got != "+i "+binary {
				t.Errorf("last chattr call = %q, want immutable state restored; all calls:\n%s", got, calls)
			}

			calls, binary = run("0")
			if got := lastCall(calls); got != "-i "+binary {
				t.Errorf("last chattr call = %q, want writable state restored; all calls:\n%s", got, calls)
			}
		})
	}
}

func TestRollbackUpgradeReportsIncompleteRecovery(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			script := filepath.Join(root, rel)
			wrapper := filepath.Join(t.TempDir(), "rollback-upgrade-incomplete.sh")
			body := strings.Join([]string{
				"#!/bin/bash",
				"set -uo pipefail",
				"die() { echo \"ERROR: $1\" >&2; exit 1; }",
				"chattr() { :; }",
				"cp() { return 1; }",
				"start_services() { :; }",
				"rollback_assets() { :; }",
				extractShellFunction(t, script, "rollback_upgrade"),
				"BINARY_PATH=/bin/true",
				"binary_backup=/missing",
				"assets_stage=/tmp",
				"asset_backup=/tmp",
				"binary_was_immutable=0",
				"rollback_upgrade 'Test failure'",
				"",
			}, "\n")
			if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("/bin/bash", wrapper).CombinedOutput()
			if err == nil {
				t.Fatalf("rollback_upgrade must fail after incomplete recovery:\n%s", out)
			}
			if !strings.Contains(string(out), "rollback incomplete") {
				t.Fatalf("incomplete recovery was misreported:\n%s", out)
			}
			if strings.Contains(string(out), "rolled back to previous version") {
				t.Fatalf("incomplete recovery claimed the previous release was restored:\n%s", out)
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

func verifyingOpenSSL() string {
	return `
mktemp() {
    (umask 077; : > "$KEY_FILE")
    printf '%s\n' "$KEY_FILE"
}

openssl() {
    if [ "$1" = "pkeyutl" ] && [ "${2:-}" = "-help" ]; then
        printf '%s\n' 'Usage: pkeyutl' ' -rawin raw input'
        return 0
    fi
    if [ "$1" = "version" ]; then
        printf '%s\n' 'OpenSSL 3.0.0'
        return 0
    fi
    if [ "$1" = "pkeyutl" ]; then
        return 0
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
        printf '%s' 'good signature' > "$out"
    fi
    printf '%s' '200'
}

pkg_download() {
    printf '%s' 'good signature' > "$2"
    printf '%s' '200'
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
