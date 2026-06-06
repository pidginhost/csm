package daemon

import (
	"bytes"
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
