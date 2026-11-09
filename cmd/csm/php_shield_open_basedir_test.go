package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A pool whose open_basedir stops at the docroot cannot see the account home
// or /opt/csm. The shield's own file checks must not log a warning on every
// request there.
func TestShieldQuietUnderOpenBasedir(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Fatal("php interpreter not available; behavioral shield check requires it")
	}
	reference, err := os.ReadFile(filepath.Join("..", "..", "configs", "php_shield.php"))
	if err != nil {
		t.Fatal(err)
	}
	// Outside /tmp and /var/tmp, which the shield blocks by default.
	base, err := os.MkdirTemp(".", "shieldbasedir")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	if base, err = filepath.Abs(base); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"deployed": shieldContent, "reference": string(reference)} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(base, name)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			files := map[string]string{
				"php_shield.php": content,
				"bootstrap.php": `<?php
$_SERVER['SCRIPT_FILENAME'] = '/home/csm-shield-test/public_html/index.php';
$_SERVER['REMOTE_ADDR'] = '192.0.2.1';
require getenv('CSM_SHIELD_TEST_FILE');
`,
				"index.php": "<?php echo 'SAFE';",
			}
			for file, body := range files {
				if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(php, "-d", "open_basedir="+dir, "-d", "error_reporting=-1", "-d", "display_errors=1",
				"-d", "auto_prepend_file="+filepath.Join(dir, "bootstrap.php"), filepath.Join(dir, "index.php"))
			cmd.Env = append(os.Environ(), "CSM_SHIELD_TEST_FILE="+filepath.Join(dir, "php_shield.php"))
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("php failed: %v (output: %q)", err, out)
			}
			if strings.Contains(string(out), "open_basedir") || !strings.HasSuffix(string(out), "SAFE") {
				t.Fatalf("output = %q, want only SAFE", out)
			}
		})
	}
}
