package daemon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
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

func TestVerifyChecksumAcceptsOnlyMatchingArtifacts(t *testing.T) {
	payload := []byte("release artifact")
	sum := sha256.Sum256(payload)
	matching := fmt.Sprintf("%x  csm\n", sum)
	mismatched := strings.Repeat("0", sha256.Size*2) + "  csm\n"

	for _, script := range deploySignatureScripts() {
		t.Run(script.name, func(t *testing.T) {
			output, code := runVerifyChecksum(t, script, payload, matching)
			if code != 0 {
				t.Fatalf("verify_checksum rejected a matching artifact, exit %d:\n%s", code, output)
			}

			output, code = runVerifyChecksum(t, script, payload, mismatched)
			if code == 0 {
				t.Fatalf("verify_checksum accepted a mismatched artifact:\n%s", output)
			}
			for _, want := range []string{
				"CHECKSUM VERIFICATION FAILED",
				"Expected: " + strings.Repeat("0", sha256.Size*2),
				fmt.Sprintf("Got:      %x", sum),
			} {
				if !strings.Contains(output, want) {
					t.Errorf("checksum failure missing %q:\n%s", want, output)
				}
			}

			output, code = runVerifyChecksum(t, script, payload, "\n")
			if code == 0 {
				t.Fatalf("verify_checksum accepted an empty checksum:\n%s", output)
			}
		})
	}
}

func TestReleaseScriptsUseChecksumHelperForBinariesAndAssets(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, script := range deploySignatureScripts() {
		t.Run(script.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, script.path))
			if err != nil {
				t.Fatal(err)
			}
			body := string(data)
			if script.path == "scripts/install.sh" {
				for _, call := range []string{
					`verify_checksum "${TMPDIR}/csm" "${TMPDIR}/csm.sha256"`,
					`verify_checksum "${TMPDIR}/assets.tar.gz" "${TMPDIR}/assets.tar.gz.sha256"`,
				} {
					if strings.Count(body, call) != 1 {
						t.Errorf("%s must make exactly one checksum call %q", script.path, call)
					}
				}
				return
			}

			packageDownload := shellFunctionBody(t, body, "download_package")
			if strings.Count(packageDownload, `verify_checksum "${tmpdir}/${ARTIFACT_NAME}" "${tmpdir}/${ARTIFACT_NAME}.sha256"`) != 1 {
				t.Errorf("%s download_package must verify the downloaded binary exactly once", script.path)
			}
			assetDownload := shellFunctionBody(t, body, "download_and_stage_assets")
			if strings.Count(assetDownload, `verify_checksum "$archive" "$checksum"`) != 1 {
				t.Errorf("%s download_and_stage_assets must verify the asset archive exactly once", script.path)
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
			start := strings.LastIndex(upgradeBody, "if ! start_services; then")
			cleanup := strings.Index(upgradeBody, `cleanup_upgrade_backup "$tmpdir"`)
			if start < 0 || cleanup < 0 || cleanup < start {
				t.Errorf("%s must keep rollback material until start_services succeeds", rel)
			}
			if strings.Count(upgradeBody, `if ! "$BINARY_PATH" rehash`) != 1 {
				t.Errorf("%s must have exactly one primary upgrade rehash", rel)
			}
		})
	}
}

// Only the GitHub deploy script resolves release tags; a release published
// mid-run must not put the binary and the assets on different versions.
func TestDeployPinsReleaseTagAcrossArtifacts(t *testing.T) {
	root := repoRootFromDaemonTest()
	githubData, err := os.ReadFile(filepath.Join(root, "scripts/deploy.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range []string{"do_install", "do_upgrade"} {
		body := shellFunctionBody(t, string(githubData), fn)
		if got := strings.Count(body, "resolve_release_tag"); got != 1 {
			t.Errorf("%s resolves the GitHub release tag %d times, want exactly once", fn, got)
		}
		if !strings.Contains(body, "release_tag=$(resolve_release_tag)") {
			t.Errorf("%s must capture the resolved GitHub release tag", fn)
		}
		for _, call := range []struct {
			name string
			want string
		}{
			{name: "download_package", want: `download_package "$release_tag" "$tmpdir"`},
			{name: "download_and_stage_assets", want: `download_and_stage_assets "$release_tag" "$tmpdir"`},
		} {
			if got := strings.Count(body, call.name); got != 1 {
				t.Errorf("%s calls %s %d times, want exactly once", fn, call.name, got)
			}
			if !strings.Contains(body, call.want) {
				t.Errorf("%s must call %s with the pinned GitHub tag", fn, call.name)
			}
		}
	}

	gitlabData, err := os.ReadFile(filepath.Join(root, "scripts/deploy-gitlab.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range []string{"do_install", "do_upgrade"} {
		body := shellFunctionBody(t, string(gitlabData), fn)
		if strings.Contains(body, "resolve_release_tag") {
			t.Errorf("%s in deploy-gitlab.sh must not require a GitHub release tag", fn)
		}
		for _, call := range []struct {
			name string
			want string
		}{
			{name: "download_package", want: `download_package "latest" "$tmpdir"`},
			{name: "download_and_stage_assets", want: `download_and_stage_assets "latest" "$tmpdir"`},
		} {
			if got := strings.Count(body, call.name); got != 1 {
				t.Errorf("%s in deploy-gitlab.sh calls %s %d times, want exactly once", fn, call.name, got)
			}
			if !strings.Contains(body, call.want) {
				t.Errorf("%s in deploy-gitlab.sh missing package-registry call %q", fn, call.want)
			}
		}
	}
}

func githubReleaseTagResolverStub(rel string) string {
	if rel != "scripts/deploy.sh" {
		return ""
	}
	return "resolve_release_tag() { printf 'v0.0.0\\n'; }"
}

func TestDeployCleansTmpdirOnFailureExit(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, rel))
			if err != nil {
				t.Fatal(err)
			}
			body := string(data)
			for _, fn := range []string{"do_install", "do_upgrade"} {
				fnBody := shellFunctionBody(t, body, fn)
				trapPos := strings.Index(fnBody, `trap "rm -rf \"${tmpdir}\"" EXIT`)
				downloadPos := strings.Index(fnBody, `download_package "`)
				if trapPos < 0 {
					t.Errorf("%s %s must arm an EXIT trap that cleans its tmpdir", rel, fn)
				}
				if downloadPos < 0 || trapPos > downloadPos {
					t.Errorf("%s %s must arm cleanup before downloading the package", rel, fn)
				}
			}
			rollbackBody := shellFunctionBody(t, body, "rollback_upgrade")
			if !strings.Contains(rollbackBody, "trap - EXIT") {
				t.Errorf("%s rollback_upgrade must disarm cleanup so rollback material survives", rel)
			}
			if !strings.Contains(rollbackBody, "Rollback material kept at") {
				t.Errorf("%s rollback_upgrade must tell the operator where rollback material lives", rel)
			}
		})
	}
}

func TestDeployCleansTmpdirWhenPackageDownloadFails(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		for _, fn := range []string{"do_install", "do_upgrade"} {
			t.Run(rel+"/"+fn, func(t *testing.T) {
				installDir := t.TempDir()
				tmpdir := filepath.Join(installDir, "partial-download")
				binary := filepath.Join(installDir, "csm")
				if fn == "do_upgrade" {
					writeDeployTestFile(t, binary, "#!/bin/bash\nprintf 'csm 1.0.0\\n'\n")
					if err := os.Chmod(binary, 0o700); err != nil {
						t.Fatal(err)
					}
				}

				script := filepath.Join(root, rel)
				wrapper := filepath.Join(t.TempDir(), "download-failure.sh")
				body := strings.Join([]string{
					"#!/bin/bash",
					"set -euo pipefail",
					"die() { echo \"ERROR: $1\" >&2; exit 1; }",
					"id() { printf '0\\n'; }",
					"detect_auth_header() { :; }",
					"save_token() { :; }",
					githubReleaseTagResolverStub(rel),
					"mktemp() { mkdir -p \"$TEST_TMPDIR\"; printf '%s\\n' \"$TEST_TMPDIR\"; }",
					"download_package() {",
					"    local tmpdir=\"$2\"",
					"    mkdir -p \"$tmpdir\"",
					"    printf 'partial' > \"${tmpdir}/artifact\"",
					"    return 1",
					"}",
					extractShellFunction(t, script, fn),
					"INSTALL_DIR=\"$TEST_INSTALL_DIR\"",
					"BINARY_PATH=\"${INSTALL_DIR}/csm\"",
					"ARTIFACT_NAME=csm-linux-amd64",
					"SERVICE_NAME=csm",
					fn,
					"",
				}, "\n")
				if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("/bin/bash", wrapper)
				cmd.Env = withEnv(os.Environ(), "TEST_INSTALL_DIR="+installDir, "TEST_TMPDIR="+tmpdir)
				if out, err := cmd.CombinedOutput(); err == nil {
					t.Fatalf("%s must fail when the package download fails:\n%s", fn, out)
				}
				if _, err := os.Stat(tmpdir); !os.IsNotExist(err) {
					t.Fatalf("partial package directory survived %s failure: %s (error: %v)", fn, tmpdir, err)
				}
			})
		}
	}
}

func TestInstallCleansTmpdirAfterInstallerFailure(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			installDir := t.TempDir()
			tmpdir := filepath.Join(installDir, "package")
			packageBinary := filepath.Join(t.TempDir(), "csm-new")
			writeDeployTestFile(t, packageBinary, "#!/bin/bash\nexit 1\n")
			if err := os.Chmod(packageBinary, 0o700); err != nil {
				t.Fatal(err)
			}

			script := filepath.Join(root, rel)
			wrapper := filepath.Join(t.TempDir(), "install-failure.sh")
			body := strings.Join([]string{
				"#!/bin/bash",
				"set -euo pipefail",
				"die() { echo \"ERROR: $1\" >&2; exit 1; }",
				"id() { printf '0\\n'; }",
				"detect_auth_header() { :; }",
				"save_token() { :; }",
				githubReleaseTagResolverStub(rel),
				"mktemp() { mkdir -p \"$TEST_TMPDIR\"; printf '%s\\n' \"$TEST_TMPDIR\"; }",
				"download_package() { mkdir -p \"$2\"; cp \"$TEST_PACKAGE_BINARY\" \"${2}/${ARTIFACT_NAME}\"; }",
				"download_and_stage_assets() { mkdir -p \"${2}/assets-stage\"; printf '%s\\n' \"${2}/assets-stage\"; }",
				"activate_assets() { :; }",
				"rollback_assets() { :; }",
				"cleanup_upgrade_backup() { rm -rf \"$1\"; }",
				extractShellFunction(t, script, "do_install"),
				"INSTALL_DIR=\"$TEST_INSTALL_DIR\"",
				"BINARY_PATH=\"${INSTALL_DIR}/csm\"",
				"ARTIFACT_NAME=csm-linux-amd64",
				"do_install",
				"",
			}, "\n")
			if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command("/bin/bash", wrapper)
			cmd.Env = withEnv(os.Environ(),
				"TEST_INSTALL_DIR="+installDir,
				"TEST_PACKAGE_BINARY="+packageBinary,
				"TEST_TMPDIR="+tmpdir,
			)
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("failed installer unexpectedly succeeded:\n%s", out)
			}
			if _, err := os.Stat(tmpdir); !os.IsNotExist(err) {
				t.Fatalf("package directory survived installer failure: %s (error: %v)", tmpdir, err)
			}
			if _, err := os.Stat(filepath.Join(installDir, "csm")); !os.IsNotExist(err) {
				t.Fatalf("failed installed binary survived cleanup (error: %v)", err)
			}
		})
	}
}

func TestInstallCleansBinaryAfterPlacementFailure(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		for _, failure := range []string{"copy", "chmod"} {
			t.Run(rel+"/"+failure, func(t *testing.T) {
				installDir := t.TempDir()
				tmpdir := filepath.Join(installDir, "package")
				packageBinary := filepath.Join(t.TempDir(), "csm-new")
				writeDeployTestFile(t, packageBinary, "#!/bin/bash\nexit 0\n")
				if err := os.Chmod(packageBinary, 0o700); err != nil {
					t.Fatal(err)
				}

				script := filepath.Join(root, rel)
				wrapper := filepath.Join(t.TempDir(), "install-placement-failure.sh")
				body := strings.Join([]string{
					"#!/bin/bash",
					"set -euo pipefail",
					"die() { echo \"ERROR: $1\" >&2; exit 1; }",
					"id() { printf '0\\n'; }",
					"detect_auth_header() { :; }",
					"save_token() { :; }",
					githubReleaseTagResolverStub(rel),
					"mktemp() { mkdir -p \"$TEST_TMPDIR\"; printf '%s\\n' \"$TEST_TMPDIR\"; }",
					"download_package() { command cp \"$TEST_PACKAGE_BINARY\" \"${2}/${ARTIFACT_NAME}\"; }",
					"download_and_stage_assets() { mkdir -p \"${2}/assets-stage\"; printf '%s\\n' \"${2}/assets-stage\"; }",
					"cp() {",
					"    if [ \"$TEST_FAILURE\" = copy ] && [ \"${!#}\" = \"$BINARY_PATH\" ]; then",
					"        printf partial > \"$BINARY_PATH\"",
					"        return 1",
					"    fi",
					"    command cp \"$@\"",
					"}",
					"chmod() {",
					"    if [ \"$TEST_FAILURE\" = chmod ] && [ \"${!#}\" = \"$BINARY_PATH\" ]; then return 1; fi",
					"    command chmod \"$@\"",
					"}",
					"activate_assets() { :; }",
					"rollback_assets() { :; }",
					"cleanup_upgrade_backup() { rm -rf \"$1\"; }",
					extractShellFunction(t, script, "do_install"),
					"INSTALL_DIR=\"$TEST_INSTALL_DIR\"",
					"BINARY_PATH=\"${INSTALL_DIR}/csm\"",
					"ARTIFACT_NAME=csm-linux-amd64",
					"do_install",
					"",
				}, "\n")
				if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}

				cmd := exec.Command("/bin/bash", wrapper)
				cmd.Env = withEnv(os.Environ(),
					"TEST_FAILURE="+failure,
					"TEST_INSTALL_DIR="+installDir,
					"TEST_PACKAGE_BINARY="+packageBinary,
					"TEST_TMPDIR="+tmpdir,
				)
				if out, err := cmd.CombinedOutput(); err == nil {
					t.Fatalf("%s failure unexpectedly succeeded:\n%s", failure, out)
				}
				if _, err := os.Stat(tmpdir); !os.IsNotExist(err) {
					t.Fatalf("package directory survived %s failure: %s (error: %v)", failure, tmpdir, err)
				}
				if _, err := os.Stat(filepath.Join(installDir, "csm")); !os.IsNotExist(err) {
					t.Fatalf("partial installed binary survived %s failure (error: %v)", failure, err)
				}
			})
		}
	}
}

func TestUpgradeHandlesBinaryPlacementFailures(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		for _, failure := range []string{"backup", "copy", "chmod"} {
			t.Run(rel+"/"+failure, func(t *testing.T) {
				installDir := t.TempDir()
				tmpdir := filepath.Join(installDir, "package")
				stopped := filepath.Join(t.TempDir(), "stopped")
				started := filepath.Join(t.TempDir(), "started")
				binary := filepath.Join(installDir, "csm")
				packageBinary := filepath.Join(t.TempDir(), "csm-new")
				for path, version := range map[string]string{binary: "1.0.0", packageBinary: "2.0.0"} {
					body := "#!/bin/bash\ncase \"${1:-}\" in\nversion) printf 'csm " + version + "\\n' ;;\nrehash) exit 0 ;;\nesac\n"
					writeDeployTestFile(t, path, body)
					if err := os.Chmod(path, 0o700); err != nil {
						t.Fatal(err)
					}
				}

				script := filepath.Join(root, rel)
				wrapper := filepath.Join(t.TempDir(), "upgrade-placement-failure.sh")
				body := strings.Join([]string{
					"#!/bin/bash",
					"set -euo pipefail",
					"die() { echo \"ERROR: $1\" >&2; exit 1; }",
					"id() { printf '0\\n'; }",
					"detect_auth_header() { :; }",
					"save_token() { :; }",
					githubReleaseTagResolverStub(rel),
					"mktemp() { mkdir -p \"$TEST_TMPDIR\"; printf '%s\\n' \"$TEST_TMPDIR\"; }",
					"download_package() { command cp \"$TEST_PACKAGE_BINARY\" \"${2}/${ARTIFACT_NAME}\"; }",
					"download_and_stage_assets() { mkdir -p \"${2}/assets-stage\"; printf '%s\\n' \"${2}/assets-stage\"; }",
					"cp() {",
					"    local destination=\"${!#}\"",
					"    if [ \"$TEST_FAILURE\" = backup ] && [ \"${1:-}\" = -p ] && [ \"$destination\" != \"$BINARY_PATH\" ]; then return 1; fi",
					"    if [ \"$TEST_FAILURE\" = copy ] && [ \"${1:-}\" != -p ] && [ \"$destination\" = \"$BINARY_PATH\" ]; then",
					"        printf partial > \"$BINARY_PATH\"",
					"        return 1",
					"    fi",
					"    command cp \"$@\"",
					"}",
					"chmod() {",
					"    if [ \"$TEST_FAILURE\" = chmod ] && [ \"${!#}\" = \"$BINARY_PATH\" ]; then return 1; fi",
					"    command chmod \"$@\"",
					"}",
					"stop_services() { : > \"$TEST_STOPPED\"; }",
					"start_services() { : > \"$TEST_STARTED\"; }",
					"activate_assets() { :; }",
					"rollback_assets() { :; }",
					"lsattr() { :; }",
					"chattr() { :; }",
					"cleanup_upgrade_backup() { rm -rf \"$1\"; }",
					extractShellFunction(t, script, "rollback_upgrade"),
					extractShellFunction(t, script, "do_upgrade"),
					"INSTALL_DIR=\"$TEST_INSTALL_DIR\"",
					"BINARY_PATH=\"${INSTALL_DIR}/csm\"",
					"ARTIFACT_NAME=csm-linux-amd64",
					"SERVICE_NAME=csm",
					"do_upgrade",
					"",
				}, "\n")
				if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}

				cmd := exec.Command("/bin/bash", wrapper)
				cmd.Env = withEnv(os.Environ(),
					"TEST_FAILURE="+failure,
					"TEST_INSTALL_DIR="+installDir,
					"TEST_PACKAGE_BINARY="+packageBinary,
					"TEST_STARTED="+started,
					"TEST_STOPPED="+stopped,
					"TEST_TMPDIR="+tmpdir,
				)
				out, err := cmd.CombinedOutput()
				if err == nil {
					t.Fatalf("%s failure unexpectedly succeeded:\n%s", failure, out)
				}

				versionOut, versionErr := exec.Command(binary, "version").CombinedOutput()
				if versionErr != nil || !strings.Contains(string(versionOut), "csm 1.0.0") {
					t.Fatalf("current binary was not preserved after %s failure: %v\n%s", failure, versionErr, versionOut)
				}
				if failure == "backup" {
					if _, err := os.Stat(stopped); !os.IsNotExist(err) {
						t.Fatalf("service was stopped despite backup failure (error: %v)", err)
					}
					if _, err := os.Stat(tmpdir); !os.IsNotExist(err) {
						t.Fatalf("package directory survived backup failure: %v", err)
					}
					return
				}

				for _, path := range []string{stopped, started, filepath.Join(tmpdir, "csm-linux-amd64.previous")} {
					if _, err := os.Stat(path); err != nil {
						t.Errorf("expected recovery state missing after %s failure: %s: %v", failure, path, err)
					}
				}
				if !strings.Contains(string(out), "Rollback material kept at "+tmpdir) {
					t.Errorf("rollback did not report preserved material after %s failure:\n%s", failure, out)
				}
			})
		}
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

func TestUpgradeChecksVersionBeforeStagingAssets(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, rel))
			if err != nil {
				t.Fatal(err)
			}
			upgradeBody := shellFunctionBody(t, string(data), "do_upgrade")

			staging := strings.Index(upgradeBody, "download_and_stage_assets")
			sameVersion := strings.Index(upgradeBody, "Already running the latest version.")
			if staging < 0 || sameVersion < 0 {
				t.Fatalf("%s do_upgrade missing staging or same-version handling", rel)
			}
			if staging < sameVersion {
				t.Errorf("%s must confirm a new version exists before downloading and staging assets", rel)
			}

			block := upgradeBody[sameVersion:]
			end := strings.Index(block, "fi")
			if end < 0 || !strings.Contains(block[:end], "start_services") {
				t.Errorf("%s same-version path must ensure the daemon is running", rel)
			}
		})
	}
}

func TestUpgradeTmpdirLifecycle(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		for _, releaseVersion := range []string{"1.0.0", "2.0.0"} {
			name := "new-version"
			if releaseVersion == "1.0.0" {
				name = "same-version"
			}
			t.Run(rel+"/"+name, func(t *testing.T) {
				installDir := t.TempDir()
				tmpdir := filepath.Join(installDir, "package")
				started := filepath.Join(t.TempDir(), "started")
				staged := filepath.Join(t.TempDir(), "staged")
				binary := filepath.Join(installDir, "csm")
				packageBinary := filepath.Join(t.TempDir(), "csm-new")
				for path, version := range map[string]string{binary: "1.0.0", packageBinary: releaseVersion} {
					body := "#!/bin/bash\ncase \"${1:-}\" in\nversion) printf 'csm " + version + "\\n' ;;\nrehash) exit 0 ;;\nesac\n"
					writeDeployTestFile(t, path, body)
					if err := os.Chmod(path, 0o700); err != nil {
						t.Fatal(err)
					}
				}

				script := filepath.Join(root, rel)
				wrapper := filepath.Join(t.TempDir(), "upgrade.sh")
				body := strings.Join([]string{
					"#!/bin/bash",
					"set -euo pipefail",
					"die() { echo \"ERROR: $1\" >&2; exit 1; }",
					"id() { printf '0\\n'; }",
					"detect_auth_header() { :; }",
					"save_token() { :; }",
					githubReleaseTagResolverStub(rel),
					"mktemp() { mkdir -p \"$TEST_TMPDIR\"; printf '%s\\n' \"$TEST_TMPDIR\"; }",
					"download_package() {",
					"    local tmpdir=\"$2\"",
					"    mkdir -p \"$tmpdir\"",
					"    cp \"$TEST_PACKAGE_BINARY\" \"${tmpdir}/${ARTIFACT_NAME}\"",
					"}",
					"download_and_stage_assets() {",
					"    local stage=\"${2}/assets-stage\"",
					"    : > \"$TEST_STAGED\"",
					"    mkdir -p \"$stage\"",
					"    printf '%s\\n' \"$stage\"",
					"}",
					"stop_services() { :; }",
					"start_services() { : > \"$TEST_STARTED\"; }",
					"activate_assets() { :; }",
					"lsattr() { :; }",
					"chattr() { :; }",
					"cleanup_upgrade_backup() { rm -rf \"$1\"; }",
					extractShellFunction(t, script, "do_upgrade"),
					"INSTALL_DIR=\"$TEST_INSTALL_DIR\"",
					"BINARY_PATH=\"${INSTALL_DIR}/csm\"",
					"ARTIFACT_NAME=csm-linux-amd64",
					"SERVICE_NAME=csm",
					"do_upgrade",
					"",
				}, "\n")
				if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("/bin/bash", wrapper)
				cmd.Env = withEnv(os.Environ(),
					"TEST_INSTALL_DIR="+installDir,
					"TEST_PACKAGE_BINARY="+packageBinary,
					"TEST_STARTED="+started,
					"TEST_STAGED="+staged,
					"TEST_TMPDIR="+tmpdir,
				)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("upgrade failed: %v\n%s", err, out)
				}
				if _, err := os.Stat(tmpdir); !os.IsNotExist(err) {
					t.Errorf("package directory survived successful upgrade path: %s (error: %v)", tmpdir, err)
				}
				if _, err := os.Stat(started); err != nil {
					t.Errorf("upgrade did not ensure the service was running: %v", err)
				}
				_, stageErr := os.Stat(staged)
				if releaseVersion == "1.0.0" && !os.IsNotExist(stageErr) {
					t.Errorf("same-version upgrade staged assets (error: %v)", stageErr)
				}
				if releaseVersion == "2.0.0" && stageErr != nil {
					t.Errorf("new-version upgrade did not stage assets: %v", stageErr)
				}
			})
		}
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
				tmpdir := filepath.Join(dir, "rollback-material")
				if err := os.Mkdir(tmpdir, 0o700); err != nil {
					t.Fatal(err)
				}
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
					"tmpdir=\"$TEST_TMPDIR\"",
					"binary_was_immutable=" + wasImmutable,
					"trap \"rm -rf \\\"${tmpdir}\\\"\" EXIT",
					"rollback_upgrade 'Test failure'",
					"",
				}, "\n")
				if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("/bin/bash", wrapper)
				cmd.Env = withEnv(os.Environ(), "CHATTR_CAPTURE="+capture, "TEST_BINARY="+binary, "TEST_TMPDIR="+tmpdir)
				out, runErr := cmd.CombinedOutput()
				calls := ""
				if data, readErr := os.ReadFile(capture); readErr == nil {
					calls = string(data)
				}
				if runErr == nil {
					t.Fatalf("rollback_upgrade must die, but exited 0:\n%s", out)
				}
				if _, statErr := os.Stat(tmpdir); statErr != nil {
					t.Fatalf("rollback material was removed despite trap disarm: %v\n%s", statErr, out)
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

func TestRollbackUpgradeDisarmsCleanupBeforeRecovery(t *testing.T) {
	root := repoRootFromDaemonTest()
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		t.Run(rel, func(t *testing.T) {
			tmpdir := filepath.Join(t.TempDir(), "rollback-material")
			if err := os.Mkdir(tmpdir, 0o700); err != nil {
				t.Fatal(err)
			}

			script := filepath.Join(root, rel)
			wrapper := filepath.Join(t.TempDir(), "rollback-upgrade-interrupted.sh")
			body := strings.Join([]string{
				"#!/bin/bash",
				"set -euo pipefail",
				"die() { exit 1; }",
				"chattr() { :; }",
				"cp() { exit 70; }",
				"start_services() { :; }",
				"rollback_assets() { :; }",
				extractShellFunction(t, script, "rollback_upgrade"),
				"BINARY_PATH=/bin/true",
				"binary_backup=/missing",
				"assets_stage=/tmp",
				"asset_backup=/tmp",
				"tmpdir=\"$TEST_TMPDIR\"",
				"binary_was_immutable=0",
				"trap \"rm -rf \\\"${tmpdir}\\\"\" EXIT",
				"rollback_upgrade 'Test failure'",
				"",
			}, "\n")
			if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command("/bin/bash", wrapper)
			cmd.Env = withEnv(os.Environ(), "TEST_TMPDIR="+tmpdir)
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("interrupted rollback unexpectedly succeeded:\n%s", out)
			}
			if _, err := os.Stat(tmpdir); err != nil {
				t.Fatalf("interrupted rollback removed recovery material: %v", err)
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
				"tmpdir=/tmp",
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

func TestInstallGuardsCatchDanglingSymlinksAndFailedBootstrap(t *testing.T) {
	root := repoRootFromDaemonTest()

	installBody, err := os.ReadFile(filepath.Join(root, "scripts/install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	install := string(installBody)
	guardStart := strings.Index(install, "# Check existing installation")
	guardEnd := strings.Index(install, "ARCH=$(detect_arch)")
	if guardStart < 0 || guardEnd < guardStart {
		t.Fatal("install.sh existing-install guard block not found")
	}
	guard := install[guardStart:guardEnd]
	if strings.Count(guard, `[ -e "$BINARY_PATH" ] || [ -L "$BINARY_PATH" ]`) != 1 {
		t.Error("install.sh already-installed guard must catch dangling symlinks")
	}
	bootstrap := `if ! "$BINARY_PATH" install; then
    rm -f "$BINARY_PATH"
    die "csm install failed; the binary was removed so install.sh can be re-run"
fi`
	if strings.Count(install, bootstrap) != 1 {
		t.Error("install.sh must remove the binary when csm install fails so a re-run can retry")
	}
	assetsOK := strings.Index(install, `info "Assets OK"`)
	configuration := strings.Index(install, "# --- Configuration ---")
	if assetsOK < 0 || configuration < assetsOK {
		t.Fatal("install.sh asset placement block not found")
	}
	placement := install[assetsOK:configuration]
	if strings.Count(placement, `chmod 755 "${INSTALL_DIR}/deploy.sh"`) != 1 || strings.Contains(placement, "|| true") {
		t.Error("install.sh must fail when chmod of the required deploy script fails")
	}

	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		installFn := shellFunctionBody(t, string(body), "do_install")
		guard := `[ -e "$BINARY_PATH" ] || [ -L "$BINARY_PATH" ]`
		if strings.Count(installFn, guard) != 1 || strings.Index(installFn, guard) > strings.Index(installFn, "mktemp") {
			t.Errorf("%s do_install guard must catch dangling symlinks", rel)
		}
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
			// Compare positions inside the next-steps block only; unrelated
			// later mentions of either string must not mask a regression.
			anchor := strings.Index(body, "ext steps")
			if anchor < 0 {
				t.Fatalf("%s has no next-steps block", rel)
			}
			block := body[anchor:]
			if len(block) > 600 {
				block = block[:600]
			}
			start := strings.Index(block, "systemctl enable --now csm.service")
			baseline := strings.Index(block, "baseline")
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

	// The deploy scripts may re-arm chattr +i only inside rollback_upgrade,
	// which restores the pre-upgrade state it observed.
	for _, rel := range []string{"scripts/deploy.sh", "scripts/deploy-gitlab.sh"} {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		rollback := shellFunctionBody(t, text, "rollback_upgrade")
		const immutableCommand = "chattr +i"
		if strings.Count(rollback, immutableCommand) != 1 {
			t.Errorf("%s rollback_upgrade must contain exactly one immutable-state restoration", rel)
			continue
		}
		allowed := strings.Index(text, rollback) + strings.Index(rollback, immutableCommand)
		for offset := 0; ; {
			found := strings.Index(text[offset:], immutableCommand)
			if found < 0 {
				break
			}
			found += offset
			if found != allowed {
				t.Errorf("%s must not apply chattr +i outside rollback state restoration", rel)
			}
			offset = found + len(immutableCommand)
		}
	}

	posttrans, err := os.ReadFile(filepath.Join(root, "build/packaging/scripts/posttrans.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(posttrans), "/opt/csm/csm config apply-immutability") {
		t.Fatal("posttrans must restore the configured immutable state")
	}
	if strings.Contains(string(posttrans), "apply-immutability 2>/dev/null") {
		t.Error("posttrans must not silence apply-immutability diagnostics")
	}
}

func TestPosttransReportsImmutabilityFailureWithoutFailing(t *testing.T) {
	root := repoRootFromDaemonTest()
	posttrans, err := os.ReadFile(filepath.Join(root, "build/packaging/scripts/posttrans.sh"))
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	fakeCSM := filepath.Join(tmp, "csm")
	fakeBody := strings.Join([]string{
		"#!/bin/bash",
		"if [ \"${APPLY_EXIT:-0}\" -ne 0 ]; then",
		"    echo 'apply-immutability diagnostic' >&2",
		"fi",
		"exit \"${APPLY_EXIT:-0}\"",
		"",
	}, "\n")
	if err := os.WriteFile(fakeCSM, []byte(fakeBody), 0o700); err != nil {
		t.Fatal(err)
	}

	wrapper := filepath.Join(tmp, "posttrans.sh")
	body := strings.ReplaceAll(string(posttrans), "/opt/csm/csm", fakeCSM)
	body = strings.ReplaceAll(body, "/var/lib/csm", filepath.Join(tmp, "state"))
	if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		exit       string
		wantWarn   bool
		wantDetail bool
	}{
		{name: "success", exit: "0"},
		{name: "failure", exit: "1", wantWarn: true, wantDetail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("/bin/bash", wrapper)
			cmd.Env = withEnv(os.Environ(), "APPLY_EXIT="+tc.exit)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("posttrans must not fail the package transaction: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
			}
			if got := strings.Contains(stderr.String(), "WARNING: could not apply configured binary immutability"); got != tc.wantWarn {
				t.Errorf("warning present = %t, want %t; stderr:\n%s", got, tc.wantWarn, stderr.String())
			}
			if got := strings.Contains(stderr.String(), "apply-immutability diagnostic"); got != tc.wantDetail {
				t.Errorf("command diagnostic present = %t, want %t; stderr:\n%s", got, tc.wantDetail, stderr.String())
			}
			if strings.Contains(stdout.String(), "WARNING") {
				t.Errorf("warning must be written to stderr, got stdout:\n%s", stdout.String())
			}
		})
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

func runVerifyChecksum(t *testing.T, script deploySignatureScript, payload []byte, checksum string) (string, int) {
	t.Helper()

	tmp := t.TempDir()
	artifact := filepath.Join(tmp, "csm")
	checksumFile := artifact + ".sha256"
	if err := os.WriteFile(artifact, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checksumFile, []byte(checksum), 0o600); err != nil {
		t.Fatal(err)
	}

	wrapper := filepath.Join(tmp, "verify-checksum.sh")
	body := strings.Join([]string{
		"#!/bin/bash",
		"set -euo pipefail",
		"die() { echo \"ERROR: $1\" >&2; exit 1; }",
		extractShellFunction(t, filepath.Join(repoRootFromDaemonTest(), script.path), "verify_checksum"),
		"verify_checksum \"$ARTIFACT\" \"$CHECKSUM_FILE\"",
		"",
	}, "\n")
	if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("/bin/bash", wrapper)
	cmd.Env = withEnv(os.Environ(), "ARTIFACT="+artifact, "CHECKSUM_FILE="+checksumFile)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(out), exitErr.ExitCode()
	}
	t.Fatalf("running checksum wrapper failed: %v\n%s", err, out)
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
	return shellFunctionBody(t, string(data), name)
}

func shellFunctionBody(t *testing.T, script, name string) string {
	t.Helper()
	start := strings.Index(script, name+"() {")
	if start < 0 {
		t.Fatalf("%s not found", name)
	}
	depth := 0
	opened := false
	for offset, char := range script[start:] {
		switch char {
		case '{':
			depth++
			opened = true
		case '}':
			depth--
			if opened && depth == 0 {
				return script[start : start+offset+1]
			}
		}
	}
	t.Fatalf("%s body did not close", name)
	return ""
}

func TestShellFunctionBodyExcludesCommandsAfterClosingBrace(t *testing.T) {
	script := "rollback_upgrade() {\n    if true; then\n        chattr +i /opt/csm/csm\n    fi\n}; chattr +i /tmp/unconditional\n"
	body := shellFunctionBody(t, script, "rollback_upgrade")
	if strings.Contains(body, "/tmp/unconditional") {
		t.Fatalf("function extraction included a command after its closing brace:\n%s", body)
	}
	if !strings.Contains(body, "/opt/csm/csm") {
		t.Fatalf("function extraction omitted the function body:\n%s", body)
	}
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
