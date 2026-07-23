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

// TestShieldBlocksDirectWebshellExecution runs the shield as a real PHP
// auto_prepend against fake webshells, normal front-controller traffic, and
// legitimate direct-entry scripts. It exercises both the deployed shield and
// the documented reference copy so their behavior cannot drift.
func TestShieldBlocksDirectWebshellExecution(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Fatal("php interpreter not available; behavioral shield check requires it")
	}

	reference, err := os.ReadFile(filepath.Join("..", "..", "configs", "php_shield.php"))
	if err != nil {
		t.Fatal(err)
	}
	shields := []struct {
		name    string
		content string
	}{
		{name: "deployed", content: shieldContent},
		{name: "reference", content: string(reference)},
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

	bootstrap := filepath.Join(base, "bootstrap.php")
	bootstrapContent := `<?php
$_SERVER['REMOTE_ADDR'] = '192.0.2.1';
$_SERVER['REQUEST_URI'] = '/shield-test';
$_SERVER['HTTP_USER_AGENT'] = 'shield-test';
$param = getenv('CSM_SHIELD_TEST_PARAM');
if ($param !== false && $param !== '') {
    $_GET[$param] = 'test';
    $_REQUEST[$param] = 'test';
}
require getenv('CSM_SHIELD_TEST_FILE');
`
	if err := os.WriteFile(bootstrap, []byte(bootstrapContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name         string
		rel          string
		body         string
		requestParam string
		blocked      bool
		logged       bool
	}{
		{"exec_sink_shell", "wp-content/plugins/galex_x/cox.php",
			"<?php if ($_REQUEST['px'] === 'k') { system($_REQUEST['c']); }", "", true, true},
		{"exec_sink_exec", "wp-content/plugins/evil/exec.php",
			"<?php function run() { exec($_GET['c']); } echo 'UNSAFE';", "", true, true},
		{"fully_qualified_exec_sink", "wp-content/plugins/evil/qualified.php",
			"<?php function run() { \\exec($_GET['c']); } echo 'UNSAFE';", "", true, true},
		{"packed_eval_in_cache", "wp-content/cache/rrhe.php",
			"<?php eval(gzinflate(base64_decode('AAAA')));", "", true, true},
		{"blocked_upload_index", "wp-content/uploads/index.php",
			"<?php echo 'SAFE';", "", true, true},
		{"index_named_plugin_webshell", "wp-content/plugins/evil/index.php",
			"<?php function run() { system($_GET['c']); } echo 'UNSAFE';", "", true, true},
		{"legit_get_only_plugin_endpoint", "wp-content/plugins/woocommerce/api.php",
			"<?php echo isset($_GET['c']) ? 'SAFE' : 'MISSING';", "c", false, true},
		{"legit_pdo_method_exec", "wp-content/plugins/foo/db.php",
			"<?php function save($pdo) { $pdo->exec('SELECT 1'); } echo $_GET['c'] ? 'SAFE' : 'MISSING';", "c", false, true},
		{"legit_spaced_method_exec", "wp-content/plugins/foo/spaced-db.php",
			"<?php function save($pdo) { $pdo -> /* driver method */ exec('SELECT 1'); } echo $_GET['c'] ? 'SAFE' : 'MISSING';", "c", false, true},
		{"legit_static_method_exec", "wp-content/plugins/foo/static-db.php",
			"<?php function save() { Database :: exec('SELECT 1'); } echo $_GET['c'] ? 'SAFE' : 'MISSING';", "c", false, true},
		{"legit_exec_function_declaration", "wp-content/plugins/foo/namespaced.php",
			"<?php namespace ShieldTest; function exec($value) { return $value; } echo $_GET['c'] ? 'SAFE' : 'MISSING';", "c", false, true},
		{"legit_sink_names_in_comments_and_strings", "wp-content/plugins/foo/help.php",
			"<?php // Never call exec(\n$help = 'eval(base64_decode('; echo $_GET['c'] ? 'SAFE' : $help;", "c", false, true},
		{"legit_base64_decode_without_eval", "wp-content/plugins/foo/decode.php",
			"<?php echo base64_decode('U0FGRQ==');", "", false, false},
		{"normal_wordpress_front_controller", "index.php",
			"<?php function dormant_shell() { system($_GET['c']); } echo 'SAFE';", "c", false, true},
	}
	for _, shieldCase := range shields {
		t.Run(shieldCase.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					caseDir := filepath.Join(base, shieldCase.name, tc.name)
					logPath := filepath.Join(caseDir, "events.log")
					content := strings.ReplaceAll(
						shieldCase.content,
						"/var/log/csm-php-shield/events.log",
						filepath.ToSlash(logPath),
					)
					shield := filepath.Join(caseDir, "php_shield.php")
					script := filepath.Join(caseDir, tc.rel)
					if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(shield, []byte(content), 0o644); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(script, []byte(tc.body), 0o644); err != nil {
						t.Fatal(err)
					}

					cmd := exec.Command(php, "-d", "auto_prepend_file="+bootstrap, script)
					cmd.Env = append(os.Environ(),
						"CSM_SHIELD_TEST_FILE="+shield,
						"CSM_SHIELD_TEST_PARAM="+tc.requestParam,
					)
					out, err := cmd.CombinedOutput()
					if err != nil {
						t.Fatalf("php failed: %v (output: %q)", err, string(out))
					}
					blocked := strings.Contains(string(out), "403 Forbidden")
					if blocked != tc.blocked {
						t.Errorf("blocked=%v, want %v (output: %q)", blocked, tc.blocked, string(out))
					}
					if !tc.blocked && !strings.Contains(string(out), "SAFE") {
						t.Errorf("safe script did not run (output: %q)", string(out))
					}

					logged := false
					if data, readErr := os.ReadFile(logPath); readErr == nil {
						logged = strings.Contains(string(data), "ua=shield-test details=")
					} else if !os.IsNotExist(readErr) {
						t.Fatal(readErr)
					}
					if logged != tc.logged {
						t.Errorf("event logged=%v, want %v", logged, tc.logged)
					}
				})
			}
		})
	}
}
