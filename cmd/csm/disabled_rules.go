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
	for _, name := range signatures.NewScanner(rulesDir).RuleNames() {
		known[strings.ToLower(name)] = struct{}{}
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
	for _, name := range disabled {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		if _, ok := known[strings.ToLower(trimmed)]; ok {
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
	var names []string
	for _, pattern := range []string{"*.yar", "*.yara"} {
		matches, _ := filepath.Glob(filepath.Join(rulesDir, pattern))
		for _, path := range matches {
			// #nosec G304 -- Glob supplies paths under the operator-configured rules dir.
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				if name := yara.RuleNameFromLine(strings.TrimSpace(line)); name != "" {
					names = append(names, name)
				}
			}
		}
	}
	return names
}
