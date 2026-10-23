package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeployInstallWorkerPermissions(t *testing.T) {
	for _, rel := range append([]string{"scripts/install.sh"}, deployScriptPaths...) {
		t.Run(rel, func(t *testing.T) {
			root := t.TempDir()
			installDir := filepath.Join(root, "install")
			if err := os.Mkdir(installDir, 0700); err != nil {
				t.Fatal(err)
			}
			pkg := filepath.Join(root, "package")
			writeDeployTestFile(t, filepath.Join(pkg, "csm"), "#!/bin/bash\nexit 0\n")
			writeDeployTestFile(t, filepath.Join(installDir, "deploy.sh"), "#!/bin/bash\nexit 0\n")
			script := filepath.Join(repoRootFromDaemonTest(), rel)
			body := []string{
				"set -euo pipefail", "umask 077", "ARTIFACT_NAME=csm",
				"die() { echo \"$1\" >&2; exit 1; }", "id() { echo 0; }",
				"detect_auth_header() { :; }", "save_token() { :; }", githubReleaseTagResolverStub(rel),
				"download_package() { cp \"$TEST_PACKAGE/csm\" \"$2/csm\"; }",
				"download_and_stage_assets() { echo \"$2/stage\"; }",
				"activate_assets() { :; }", "rollback_assets() { :; }",
				"cleanup_upgrade_backup() { :; }",
			}
			if rel == "scripts/install.sh" {
				data, err := os.ReadFile(script)
				if err != nil {
					t.Fatal(err)
				}
				start := strings.Index(string(data), "## Place binary")
				end := strings.Index(string(data), "# --- Configuration ---")
				if start < 0 || end < start {
					t.Fatal("binary installation block not found")
				}
				body = append(body, "TMPDIR=\"$TEST_PACKAGE\"", string(data[start:end]))
			} else {
				body = append(body, extractShellFunction(t, script, "do_install"), "do_install")
			}
			wrapper := filepath.Join(root, "install.sh")
			writeDeployTestFile(t, wrapper, strings.Join(body, "\n"))
			cmd := exec.Command("/bin/bash", wrapper)
			cmd.Env = withEnv(os.Environ(), "INSTALL_DIR="+installDir, "BINARY_PATH="+filepath.Join(installDir, "csm"), "TEST_PACKAGE="+pkg)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("install: %v\n%s", err, out)
			}
			for _, path := range []string{installDir, filepath.Join(installDir, "csm")} {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0711 {
					t.Errorf("%s mode = %#o, want 0711", path, info.Mode().Perm())
				}
			}
		})
	}
}
