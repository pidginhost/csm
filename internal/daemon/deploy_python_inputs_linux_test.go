//go:build linux

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPythonReleaseVerifierBoundsInputs(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("Python verifier tests require python3-cryptography")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	payload := []byte("release payload")
	for _, script := range deploySignatureScripts() {
		for _, input := range []string{"valid", "oversized key", "FIFO key", "FIFO signature", "FIFO artifact"} {
			t.Run(script.name+"/"+input, func(t *testing.T) {
				dir := t.TempDir()
				paths := []string{filepath.Join(dir, "key"), filepath.Join(dir, "sig"), filepath.Join(dir, "artifact")}
				data := [][]byte{key, ed25519.Sign(private, payload), payload}
				if input == "oversized key" {
					data[0] = append(append([]byte(nil), key...), []byte(strings.Repeat(" ", (1<<16)+1-len(key)))...)
				}
				for i, path := range paths {
					if input == "FIFO "+[]string{"key", "signature", "artifact"}[i] {
						if err := unix.Mkfifo(path, 0600); err != nil {
							t.Fatal(err)
						}
					} else if err := os.WriteFile(path, data[i], 0600); err != nil {
						t.Fatal(err)
					}
				}
				wrapper := strings.Join([]string{
					"set -euo pipefail",
					// Replace the shell with Python so the deadline kills the
					// blocked interpreter as well as its parent on a regression.
					`python3() { exec "$PYTHON_BINARY" "$@"; }`,
					extractShellFunction(t, filepath.Join(repoRootFromDaemonTest(), script.path), "verify_with_python"),
					`verify_with_python "$KEY_PATH" "$SIG_PATH" "$ARTIFACT_PATH"`,
				}, "\n")
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "/bin/bash", "-c", wrapper)
				cmd.Env = withEnv(os.Environ(), "PYTHON_BINARY="+python, "KEY_PATH="+paths[0], "SIG_PATH="+paths[1], "ARTIFACT_PATH="+paths[2])
				output, err := cmd.CombinedOutput()
				if ctx.Err() != nil {
					t.Fatal("Python verifier blocked on a non-regular input")
				}
				if (err == nil) != (input == "valid") {
					t.Fatalf("verification: %v\n%s", err, output)
				}
			})
		}
	}
}
