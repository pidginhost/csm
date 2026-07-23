package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The galex fake-plugin webshell (2026-07-23) executed because the shield
// path-allowlisted cache directories and never inspected plugin/theme code.
// These exceptions must be gone.
func TestShieldDropsPathAllowlist(t *testing.T) {
	for _, forbidden := range []string{"'/cache/'", "'/sucuri/'", "'/smush/'", "'/imunify'"} {
		if strings.Contains(shieldContent, forbidden) {
			t.Errorf("shield still path-allowlists %s (never-allowlist-paths)", forbidden)
		}
	}
}

func TestShieldHasWebshellContentDetection(t *testing.T) {
	for _, want := range []string{"csm_is_webshell", "csm_has_exec_sink"} {
		if !strings.Contains(shieldContent, want) {
			t.Errorf("shield missing %s helper", want)
		}
	}
}

// TestShieldBlocksDirectWebshellExecution runs the shield as a real PHP
// auto_prepend against fake webshell and legit scripts.
func TestShieldBlocksDirectWebshellExecution(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("php interpreter not available; behavioral shield check requires it")
	}

	// The shield's default blocked_paths include /tmp and /var/tmp, so the fake
	// docroot must live outside them; build it under the package dir rather than
	// t.TempDir() (which resolves under /tmp on Linux and would path-block all).
	base, err := os.MkdirTemp(".", "shieldtest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	if base, err = filepath.Abs(base); err != nil {
		t.Fatal(err)
	}

	shield := filepath.Join(base, "php_shield.php")
	if err := os.WriteFile(shield, []byte(shieldContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		rel     string
		body    string
		blocked bool
	}{
		{"exec_sink_shell", "wp-content/plugins/galex_x/cox.php",
			"<?php if ($_REQUEST['px'] === 'k') { system($_REQUEST['c']); }", true},
		{"packed_eval_in_cache", "wp-content/cache/rrhe.php",
			"<?php eval(gzinflate(base64_decode('AAAA')));", true},
		{"legit_plugin_endpoint", "wp-content/plugins/woocommerce/api.php",
			"<?php echo 'ok'; function add($a, $b) { return $a + $b; }", false},
		{"legit_pdo_method_exec", "wp-content/plugins/foo/db.php",
			"<?php $pdo->exec('SELECT 1'); echo 'ok';", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := filepath.Join(base, tc.rel)
			if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(script, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			out, _ := exec.Command(php, "-d", "auto_prepend_file="+shield, script).CombinedOutput()
			blocked := strings.Contains(string(out), "403 Forbidden")
			if blocked != tc.blocked {
				t.Errorf("%s: blocked=%v, want %v (output: %q)", tc.name, blocked, tc.blocked, string(out))
			}
		})
	}
}
