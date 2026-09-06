package daemon

import (
	"os"
	"os/exec"
	"testing"
)

// requirePythonVerifier gates the tests covering the python3-cryptography
// release verifier, the supported path on hosts whose OpenSSL cannot verify
// Ed25519. CI installs the module and sets CSM_REQUIRE_PYTHON_VERIFIER=1, so a
// missing verifier there is a failure rather than a quiet skip -- the same
// contract the clean-corpus gates use through CSM_CORPUS_REQUIRED. Local Linux
// container runs without the module skip loudly instead of failing the tree.
func requirePythonVerifier(t *testing.T) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err == nil {
		err = exec.Command(python, "-I", "-c",
			"from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey").Run()
	}
	if err == nil {
		return python
	}
	const missing = "python3-cryptography with Ed25519 support is unavailable"
	if os.Getenv("CSM_REQUIRE_PYTHON_VERIFIER") == "1" {
		t.Fatalf("CSM_REQUIRE_PYTHON_VERIFIER=1 but %s: %v", missing, err)
	}
	t.Skipf("%s; set CSM_REQUIRE_PYTHON_VERIFIER=1 to require it", missing)
	return ""
}
