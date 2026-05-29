package checks

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// --- scanErrorLogs with bloated log ----------------------------------

func TestScanErrorLogsBloated(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{
				testDirEntry{name: "error_log", isDir: false},
				testDirEntry{name: "subdir", isDir: true},
			}, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			if strings.HasSuffix(name, "error_log") {
				return fakeFileInfo{name: "error_log", size: 100 * 1024 * 1024}, nil
			}
			return fakeFileInfo{name: "subdir", size: 0}, nil
		},
	})

	var findings []alert.Finding
	scanErrorLogs("/home/alice/public_html", 5*1024*1024, 3, &findings)
	_ = findings
}

// --- scanWPConfigs with WP_DEBUG true --------------------------------

func TestScanWPConfigsDebugTrue(t *testing.T) {
	wpConfig := "<?php\ndefine('WP_DEBUG', true);\ndefine('WP_MEMORY_LIMIT', '40M');\ndefine('DB_NAME','wp');\ndefine('DB_USER','u');\ndefine('DB_PASSWORD','p');\ndefine('DB_HOST','localhost');\n"

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{testDirEntry{name: "wp-config.php", isDir: false}}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "wp-config.php") {
				return []byte(wpConfig), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	var findings []alert.Finding
	scanWPConfigs("/home/alice/public_html", "alice", cfg, 3, &findings)
	if len(findings) == 0 {
		t.Error("WP_DEBUG=true should produce a finding")
	}
}

// --- scanDirForObfuscatedPHP with obfuscated content -----------------

func TestScanDirForObfuscatedPHPWithHexContent(t *testing.T) {
	obfuscated := "<?php\n" +
		strings.Repeat(`"\\x63"."\\x75"."\\x72"."\\x6c".`, 10) + `"";` + "\n" +
		strings.Repeat("goto lbl; lbl:\n", 15)

	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			return []os.DirEntry{testDirEntry{name: "obf.php", isDir: false}}, nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "obf.php", size: int64(len(obfuscated))}, nil
		},
		open: func(name string) (*os.File, error) {
			tmp := t.TempDir() + "/obf.php"
			_ = os.WriteFile(tmp, []byte(obfuscated), 0644)
			return os.Open(tmp)
		},
	})

	var findings []alert.Finding
	scanDirForObfuscatedPHP(context.Background(), "/home/alice/public_html", 3, &config.Config{}, &findings)
	_ = findings
}

// --- analyzePHPContent with obfuscated patterns ----------------------

func TestAnalyzePHPContentWithObfuscation(t *testing.T) {
	content := "<?php\n" +
		strings.Repeat("goto x; x:\n", 15) +
		strings.Repeat(`"\\x63"."\\x75".`, 30) +
		"\n"

	dir := t.TempDir()
	path := dir + "/obf.php"
	_ = os.WriteFile(path, []byte(content), 0644)

	old := osFS
	osFS = realOS{}
	defer func() { osFS = old }()

	result := analyzePHPContent(path)
	_ = result
}

// --- analyzePHPContent: eval/assert wrapping dynamic code execution --

func analyzePHPString(t *testing.T, content string) phpAnalysisResult {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/sample.php"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	old := osFS
	osFS = realOS{}
	t.Cleanup(func() { osFS = old })
	return analyzePHPContent(path)
}

func TestAnalyzePHPContentEvalVariableCallee(t *testing.T) {
	// eval($f(...)) -- variable callee the literal-decoder regex misses.
	res := analyzePHPString(t, "<?php $f='base'.'64_decode'; eval($f($_GET['c'])); ?>")
	if res.severity < 0 {
		t.Fatal("eval($f(...)) should produce at least one indicator")
	}
	if !strings.Contains(res.details, "dynamic code-execution primitive") {
		t.Errorf("missing eval-var-callee indicator; details=%q", res.details)
	}
}

func TestAnalyzePHPContentEvalCreateFunction(t *testing.T) {
	res := analyzePHPString(t, "<?php eval(create_function('', $payload)); ?>")
	if res.severity < 0 || !strings.Contains(res.details, "dynamic code-execution primitive") {
		t.Errorf("eval(create_function(...)) not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentEvalStringLiteralNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php eval('return 1;'); ?>")
	if strings.Contains(res.details, "dynamic code-execution primitive") {
		t.Errorf("eval(string literal) wrongly flagged as dynamic exec; details=%q", res.details)
	}
}

func TestAnalyzePHPContentEvalCommentWedgedVarCallee(t *testing.T) {
	// Comment wedged between eval and ( must not defeat detection.
	res := analyzePHPString(t, "<?php eval /*x*/ ( $f($_POST['z']) ); ?>")
	if res.severity < 0 || !strings.Contains(res.details, "dynamic code-execution primitive") {
		t.Errorf("comment-wedged eval($f(...)) not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentPlainEvalNotFlagged(t *testing.T) {
	// eval($code) with no inner call is common-ish templating; the new
	// indicator must not fire on it (FP guard).
	res := analyzePHPString(t, "<?php $code = trim($tpl); eval($code); ?>")
	if strings.Contains(res.details, "dynamic code-execution primitive") {
		t.Errorf("plain eval($var) wrongly flagged as dynamic exec; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertConditionNotFlagged(t *testing.T) {
	// assert($x > 0) is a normal condition, not a callable invocation.
	res := analyzePHPString(t, "<?php function f($x){ assert($x > 0); return $x; } ?>")
	if strings.Contains(res.details, "dynamic code-execution primitive") {
		t.Errorf("assert(condition) wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertCallableConditionNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert($validator($value)); ?>")
	if strings.Contains(res.details, "dynamic code-execution primitive") {
		t.Errorf("assert($callback(...)) wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentAssertCallUserFuncConditionNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php assert(call_user_func($validator, $value)); ?>")
	if strings.Contains(res.details, "dynamic code-execution primitive") {
		t.Errorf("assert(call_user_func(...)) wrongly flagged; details=%q", res.details)
	}
}

// --- analyzePHPContent: callback / backtick / variable-variable sinks --

func TestAnalyzePHPContentBacktickSuperglobal(t *testing.T) {
	res := analyzePHPString(t, "<?php $out = `cat /etc/passwd $_GET[x]`; echo $out; ?>")
	if !strings.Contains(res.details, "backtick shell execution with request input") {
		t.Errorf("backtick with superglobal not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentBacktickNoSuperglobalNotFlagged(t *testing.T) {
	// A backtick with a static command is not a request-driven RCE.
	res := analyzePHPString(t, "<?php $v = `git rev-parse HEAD`; echo $v; ?>")
	if strings.Contains(res.details, "backtick shell execution with request input") {
		t.Errorf("static backtick wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentBacktickExampleNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php\n// Example: `cat $_GET[x]`\n$doc = \"Run `cat $_POST[x]` from a shell\";\n?>")
	if strings.Contains(res.details, "backtick shell execution with request input") {
		t.Errorf("comment or string backtick example wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentBacktickWithShellQuotesStillFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php $out = `printf \"x\" $_GET[c]`; ?>")
	if !strings.Contains(res.details, "backtick shell execution with request input") {
		t.Errorf("backtick with quoted shell args not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentCallbackExecName(t *testing.T) {
	res := analyzePHPString(t, "<?php array_map(\"system\", $_POST['cmds']); ?>")
	if !strings.Contains(res.details, "exec/decoder function name passed as a callback") {
		t.Errorf("array_map(\"system\", ...) not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentGlobalCallbackExecName(t *testing.T) {
	res := analyzePHPString(t, "<?php \\call_user_func('shell_exec', $_GET['c']); ?>")
	if !strings.Contains(res.details, "exec/decoder function name passed as a callback") {
		t.Errorf("\\call_user_func('shell_exec', ...) not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentCallbackRegisterShutdown(t *testing.T) {
	res := analyzePHPString(t, "<?php register_shutdown_function('passthru', $_GET['c']); ?>")
	if !strings.Contains(res.details, "exec/decoder function name passed as a callback") {
		t.Errorf("register_shutdown_function('passthru', ...) not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentDecoderCallbackNoRequestNotFlagged(t *testing.T) {
	// WooCommerce Payments decrypt_signed_data uses array_map('base64_decode',
	// $data) on internal data. A decoder as a callback executes nothing on its
	// own, so without request input it must not trip the callback indicator.
	res := analyzePHPString(t, "<?php $decoded = array_map('base64_decode', $data); ?>")
	if strings.Contains(res.details, "exec/decoder function name passed as a callback") {
		t.Errorf("benign decoder callback wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentDecoderCallbackRequestElsewhereNotFlagged(t *testing.T) {
	// Mirrors woopay-utilities.php: the file uses $_POST in unrelated methods,
	// but the decoder callback itself operates on internal data. The gate is
	// per-call, not file-wide, so this must not flag.
	res := analyzePHPString(t, "<?php\n"+
		"function save() { return $_POST['x']; }\n"+
		"function decrypt($data) { return array_map('base64_decode', $data); }\n"+
		"?>")
	if strings.Contains(res.details, "exec/decoder function name passed as a callback") {
		t.Errorf("decoder callback flagged on file-wide request var; details=%q", res.details)
	}
}

func TestAnalyzePHPContentDecoderCallbackWithRequestFlagged(t *testing.T) {
	// A decoder fed attacker input as a callback is the dropper shape
	// (array_map('base64_decode', $_POST['p'])) and must still flag.
	res := analyzePHPString(t, "<?php $p = array_map('base64_decode', $_POST['p']); ?>")
	if !strings.Contains(res.details, "exec/decoder function name passed as a callback") {
		t.Errorf("decoder callback fed request input not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentExecCallbackNoRequestStillFlagged(t *testing.T) {
	// An execution sink as a callback is RCE regardless of where its arguments
	// come from, so it must flag even without request input on the call.
	res := analyzePHPString(t, "<?php array_map('system', $cmds); ?>")
	if !strings.Contains(res.details, "exec/decoder function name passed as a callback") {
		t.Errorf("system callback wrongly cleared without request input; details=%q", res.details)
	}
}

func TestAnalyzePHPContentBenignCallbackNotFlagged(t *testing.T) {
	// These callback shapes are common in WordPress plugins and must not
	// trip the callback-exec indicator.
	res := analyzePHPString(t, "<?php $a = array_map('trim', $_POST); $b = array_filter($arr, 'is_string'); usort($a, 'strcmp'); call_user_func($obj, 'method'); ?>")
	if strings.Contains(res.details, "exec/decoder function name passed as a callback") {
		t.Errorf("benign callback use wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentCallbackExampleNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php\n// array_map('system', $_POST);\n$doc = \"register_shutdown_function('passthru', $_GET[c])\";\n?>")
	if strings.Contains(res.details, "exec/decoder function name passed as a callback") {
		t.Errorf("comment or string callback example wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentVarVarCallWithRequest(t *testing.T) {
	res := analyzePHPString(t, "<?php $$h($_GET['a'], $_GET['b']); ?>")
	if !strings.Contains(res.details, "variable-variable function call with request input") {
		t.Errorf("$$h($_GET...) not flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentVarVarCallNoRequestNotFlagged(t *testing.T) {
	// $$handler() dispatch without attacker input is a legitimate pattern.
	res := analyzePHPString(t, "<?php $handler='render'; $$handler($config); ?>")
	if strings.Contains(res.details, "variable-variable function call with request input") {
		t.Errorf("benign $$handler() wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentVarVarCallStringRequestNotFlagged(t *testing.T) {
	res := analyzePHPString(t, "<?php $$handler('$_GET[x]'); ?>")
	if strings.Contains(res.details, "variable-variable function call with request input") {
		t.Errorf("string-only request token wrongly flagged; details=%q", res.details)
	}
}

func TestAnalyzePHPContentNewIndicatorsSeverityThreshold(t *testing.T) {
	single := analyzePHPString(t, "<?php array_map(\"system\", $_POST['cmds']); ?>")
	if single.severity != alert.High {
		t.Errorf("single callback indicator severity = %v, want High", single.severity)
	}

	multiple := analyzePHPString(t, "<?php array_map(\"system\", $_POST['cmds']); $out = `cat $_GET[x]`; ?>")
	if multiple.severity != alert.Critical {
		t.Errorf("two new indicators severity = %v, want Critical", multiple.severity)
	}
}

// --- checkDangerousPorts with listening port on dangerous port --------

func TestCheckDangerousPortsWithListening(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/net/tcp" {
				// Port 6379 (18EB hex) in LISTEN state (0A)
				return []byte("  sl  local_address rem_address   st\n   0: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.Firewall = &firewall.FirewallConfig{Enabled: true, TCPIn: []int{22, 80, 443}}
	results := checkDangerousPorts(cfg)
	_ = results
}

// --- CheckSwapAndOOM with OOM in dmesg --------------------------------

func TestCheckSwapAndOOMWithOOMKill(t *testing.T) {
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/proc/meminfo" {
				tmp := t.TempDir() + "/meminfo"
				_ = os.WriteFile(tmp, []byte("MemTotal: 4096000 kB\nMemAvailable: 2048000 kB\nSwapTotal: 1024000 kB\nSwapFree: 512000 kB\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		run: func(name string, args ...string) ([]byte, error) {
			if name == "dmesg" {
				return []byte("[12345.678] Out of memory: Killed process 1234 (php-fpm) total-vm:1234kB\n"), nil
			}
			return nil, nil
		},
	})

	findings := CheckSwapAndOOM(context.Background(), &config.Config{}, nil)
	_ = findings
}

// --- auditVfilterFile with filter rules ------------------------------

func TestAuditVfilterFileWithRules(t *testing.T) {
	filterContent := "$header_to: contains \"info@example.com\"\n  save /dev/null\n$header_from: contains \"spammer@evil.com\"\n  pipe \"/usr/bin/malware\"\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			return []byte(filterContent), nil
		},
	})

	localDomains := map[string]bool{"example.com": true}
	findings := auditVfilterFile("/etc/vfilters/example.com", "example.com", localDomains, &config.Config{})
	_ = findings
}
