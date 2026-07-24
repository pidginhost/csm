package signatures

import "github.com/pidginhost/csm/internal/yara"

// forgeSuppressedRules returns the built-in Forge rule suppressions. The list
// and the stripping live in internal/yara so the compiler and the downloader
// agree on exactly which rules are active; see internal/yara/suppressed.go for
// the criteria an entry has to meet.
func forgeSuppressedRules() []string {
	return yara.SuppressedRuleNames()
}

// mergeDisabledRules combines operator-configured disabled rule names with the
// built-in suppressions, dropping duplicates. Built-ins apply even when the
// operator configured nothing, so a clean install does not inherit a known
// false-positive flood.
func mergeDisabledRules(operator []string) []string {
	builtin := forgeSuppressedRules()
	seen := make(map[string]struct{}, len(operator)+len(builtin))
	merged := make([]string, 0, len(operator)+len(builtin))
	for _, name := range append(builtin, operator...) {
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		merged = append(merged, name)
	}
	return merged
}
