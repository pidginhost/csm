package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/yara"
)

// validateDisabledRules checks that every name in signatures.disabled_rules
// matches a rule CSM would otherwise load. A name nobody recognises is almost
// always a typo, and a typo here reads as "that rule is off" while the rule
// keeps firing.
func validateDisabledRules(rulesDir string, disabled []string) []config.ValidationResult {
	if len(disabled) == 0 || rulesDir == "" {
		return nil
	}

	known := make(map[string]struct{})
	// Ask the loader which configured names it found before compilation.
	// A disabled rule may itself contain the regex error being worked around.
	scanner := signatures.NewScanner(rulesDir, disabled...)
	unmatched := make(map[string]bool)
	for _, name := range scanner.DisabledRulesWithoutMatch() {
		unmatched[name] = true
	}
	for _, name := range scanner.DisabledRules() {
		if !unmatched[name] {
			known[name] = struct{}{}
		}
	}
	for _, name := range yaraRuleNamesIn(rulesDir) {
		known[strings.ToLower(name)] = struct{}{}
	}
	// Built-in Forge suppressions are legitimate names to carry in config
	// even though they are stripped before anything loads them.
	for _, name := range yara.SuppressedRuleNames() {
		known[strings.ToLower(name)] = struct{}{}
	}

	var unknown []string
	matched := 0
	seen := make(map[string]bool)
	for _, name := range disabled {
		trimmed := strings.TrimSpace(name)
		normalized := strings.ToLower(trimmed)
		if trimmed == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		if _, ok := known[normalized]; ok {
			matched++
			continue
		}
		unknown = append(unknown, trimmed)
	}

	var results []config.ValidationResult
	if matched > 0 {
		results = append(results, config.ValidationResult{
			Level: "ok", Field: "signatures.disabled_rules",
			Message: fmt.Sprintf("%d rule(s) disabled", matched),
		})
	}
	if len(unknown) > 0 {
		results = append(results, config.ValidationResult{
			Level: "warn", Field: "signatures.disabled_rules",
			Message: fmt.Sprintf("no such rule: %s", strings.Join(unknown, ", ")),
		})
	}
	return results
}

// yaraRuleNamesIn reads rule names out of the .yar/.yara files in a directory
// without needing the YARA engine, so validation answers the same on a build
// without it.
func yaraRuleNamesIn(rulesDir string) []string {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range entries {
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if entry.IsDir() || (ext != ".yar" && ext != ".yara") {
			continue
		}
		// #nosec G304 -- ReadDir supplies a basename under the configured rules dir.
		data, err := os.ReadFile(filepath.Join(rulesDir, entry.Name()))
		if err != nil {
			continue
		}
		names = append(names, yara.RuleNames(data)...)
	}
	return names
}
