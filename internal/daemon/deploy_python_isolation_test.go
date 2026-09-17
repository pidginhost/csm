package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Root-run verification must not import code from the caller's working
// directory or Python module path before authenticating a release.
func TestPythonReleaseVerifierIgnoresCallerModules(t *testing.T) {
	requirePythonVerifier(t)
	for _, script := range deploySignatureScripts() {
		for _, source := range []string{"cwd", "PYTHONPATH"} {
			t.Run(script.name+"/"+source, func(t *testing.T) {
				dir := t.TempDir()
				module := filepath.Join(dir, "cryptography")
				if err := os.Mkdir(module, 0700); err != nil {
					t.Fatal(err)
				}
				marker := filepath.Join(dir, "imported")
				body := "import os\nopen(os.environ['IMPORT_MARKER'], 'w').close()\nraise RuntimeError('untrusted module imported')\n"
				if err := os.WriteFile(filepath.Join(module, "__init__.py"), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(repoRootFromDaemonTest(), script.path)
				wrapper := strings.Join([]string{
					"set -euo pipefail",
					extractShellFunction(t, path, "python_verifies_ed25519"),
					extractShellFunction(t, path, "verify_with_python"),
					"python_verifies_ed25519 || :",
					"verify_with_python /nonexistent/key /nonexistent/sig /nonexistent/artifact",
				}, "\n")
				cmd := exec.Command("/bin/bash", "-c", wrapper)
				cmd.Dir = t.TempDir()
				cmd.Env = withEnv(os.Environ(), "IMPORT_MARKER="+marker, "CSM_DISABLE_PYTHON_VERIFIER=0", "PYTHONPATH=")
				if source == "cwd" {
					cmd.Dir = dir
				} else {
					cmd.Env = withEnv(cmd.Env, "PYTHONPATH="+dir)
				}
				output, err := cmd.CombinedOutput()
				if err == nil {
					t.Fatal("accepted absent verification inputs")
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatalf("verifier executed caller-controlled Python code: %v\n%s", err, output)
				}
			})
		}
	}
}
