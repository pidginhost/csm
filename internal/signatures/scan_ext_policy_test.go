package signatures

import "testing"

// phpRuleScanner builds a scanner with one PHP-only literal-pattern rule, the
// shape every rule in configs/malware.yml uses.
func phpRuleScanner() *Scanner {
	return &Scanner{rules: []Rule{{
		Name:      "webshell_post_exec",
		FileTypes: []string{".php"},
		Patterns:  []string{"system($_POST"},
		MinMatch:  1,
	}}}
}

// A stock PHP handler executes .phtml, .pht and .php2-.php8 exactly like .php.
// Every PHP rule is written against ".php", so those names must reach the same
// rule set or a webshell hides behind the extension.
func TestPHPRulesApplyToEveryExecutablePHPExtension(t *testing.T) {
	scanner := phpRuleScanner()
	shell := []byte("<?php system($_POST['cmd']);")
	for _, ext := range []string{".php", ".phtml", ".pht", ".php5", ".php7", ".php8", ".PHTML", ".phps"} {
		if matches := scanner.ScanContent(shell, ext); len(matches) != 1 {
			t.Errorf("ext %q: matches = %d, want 1", ext, len(matches))
		}
	}
	for _, ext := range []string{".txt", ".html", ".inc", ""} {
		if matches := scanner.ScanContent(shell, ext); len(matches) != 0 {
			t.Errorf("ext %q: matches = %d, want 0 (rule is PHP-only)", ext, len(matches))
		}
	}
}

// Archive magic alone must not switch scanning off: PHP echoes the leading
// bytes and executes what follows. Only a file whose name is also an archive
// is skipped.
func TestArchiveMagicDoesNotExemptExecutableNames(t *testing.T) {
	scanner := phpRuleScanner()
	polyglot := append([]byte{'P', 'K', 0x03, 0x04}, []byte("<?php system($_POST['cmd']);")...)
	if matches := scanner.ScanContent(polyglot, ".php"); len(matches) != 1 {
		t.Fatalf("zip-prefixed .php: matches = %d, want 1", len(matches))
	}
	wildcard := &Scanner{rules: []Rule{{
		Name:      "all_files_backdoor",
		FileTypes: []string{"*"},
		Patterns:  []string{"gs-netcat"},
		MinMatch:  1,
	}}}
	archive := append([]byte{'P', 'K', 0x03, 0x04}, []byte("gs-netcat")...)
	if matches := wildcard.ScanContent(archive, ".zip"); len(matches) != 0 {
		t.Fatalf("real archive by name and magic must still be skipped: %v", matches)
	}
	if matches := wildcard.ScanContent(archive, ".dat"); len(matches) != 1 {
		t.Fatalf("archive magic under a non-archive name: matches = %d, want 1", len(matches))
	}
}
