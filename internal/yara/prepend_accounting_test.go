//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	yara_x "github.com/VirusTotal/yara-x/go"
)

// Product counts can excuse a directive only at that directive's offset, and
// only once. Check the engine's matches rather than another regex engine's
// interpretation of the shipped patterns.
func TestAutoPrependProductAccounting(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "configs", "malware.yar"))
	if err != nil {
		t.Fatal(err)
	}
	rule := regexp.MustCompile(`(?ms)^rule backdoor_htaccess_auto_prepend \{.*?^\}`).Find(source)
	condition := strings.Index(string(rule), "    condition:")
	if condition < 0 {
		t.Fatal("prepend rule not found")
	}
	// Expose matches even when the normal condition excuses a clean product.
	rules, err := yara_x.Compile(string(rule[:condition]) + "    condition: any of them\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Destroy()
	products := []string{
		"wordfence-waf.php",
		"/home/example/public_html/wordfence-waf.php",
		"/home/example/public_html/sucuri.php",
		"/home/example/public_html/wp-content/plugins/ithemes-security-pro/pro/mu-plugin/hide-backend.php",
		"/home/example/public_html/wp-content/advanced-headers.php",
		// Names embedded in another path must not count as two products.
		"/home/example/wordfence-waf.php/sucuri.php",
		"/home/example/sucuri.php/wp-content/advanced-headers.php",
	}
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		for _, indent := range []string{"", " ", "\t", "\f", "\v", " \t\f\v"} {
			for _, prefix := range []string{"php_value ", "php_admin_value ", ""} {
				for _, separator := range []string{" ", "=", " = ", "\t", "\f", "\v"} {
					var body strings.Builder
					for _, target := range products {
						for _, quote := range []string{"", "'", `"`} {
							if body.Len() != 0 {
								body.WriteString(ending + ending)
							}
							body.WriteString(indent + prefix + "auto_prepend_file" + separator + quote + target + quote + ending)
						}
					}
					results, err := rules.Scan([]byte(body.String()))
					if err != nil {
						t.Fatal(err)
					}
					if len(results.MatchingRules()) != 1 {
						t.Fatalf("no directive matches for ending %q, indent %q, prefix %q, separator %q", ending, indent, prefix, separator)
					}
					matches := results.MatchingRules()[0].Patterns()
					prepend := make(map[uint64]bool)
					for _, pattern := range matches {
						if pattern.Identifier() == "$prepend" {
							for _, match := range pattern.Matches() {
								prepend[match.Offset()] = true
							}
						}
					}
					credited := make(map[uint64]string)
					seen := make(map[string]bool)
					for _, pattern := range matches {
						switch pattern.Identifier() {
						case "$wordfence", "$ithemes", "$sucuri", "$rsssl_directive":
							for _, match := range pattern.Matches() {
								seen[pattern.Identifier()] = true
								offset := match.Offset()
								if !prepend[offset] {
									t.Fatalf("%s credited offset %d without a prepend: ending %q, indent %q, prefix %q, separator %q", pattern.Identifier(), offset, ending, indent, prefix, separator)
								}
								if prior, exists := credited[offset]; exists {
									t.Fatalf("offset %d credited by both %s and %s", offset, prior, pattern.Identifier())
								}
								credited[offset] = pattern.Identifier()
							}
						}
					}
					if prefix == "php_value " && separator == " " {
						for _, product := range []string{"$wordfence", "$ithemes", "$sucuri", "$rsssl_directive"} {
							if !seen[product] {
								t.Fatalf("%s did not match its directive with ending %q and indent %q", product, ending, indent)
							}
						}
					}
				}
			}
		}
	}
}

func TestAutoPrependHorizontalWhitespace(t *testing.T) {
	scanner := loadRepoYaraScanner(t)
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		for _, indent := range []string{"\f", "\v", " \t\f\v"} {
			clean := ending + ending + indent + "auto_prepend_file = '/home/example/wordfence-waf.php'" + ending
			if hasYaraRule(scanner.ScanBytes([]byte(clean)), "backdoor_htaccess_auto_prepend") {
				t.Errorf("clean product flagged with ending %q and indent %q", ending, indent)
			}
			attack := clean + indent + "auto_prepend_file = '/home/example/.cache/drop.php'" + ending
			if !hasYaraRule(scanner.ScanBytes([]byte(attack)), "backdoor_htaccess_auto_prepend") {
				t.Errorf("dropped prelude missed with ending %q and indent %q", ending, indent)
			}
		}
	}
}
