package yara

import "strings"

// YARA Forge aggregates community rulesets of mixed quality. Most are useful,
// but a rule whose condition ordinary code satisfies fires on every account on
// a shared host at once, and that volume hides real detections. Those rules are
// stripped both when a tier is downloaded and when rules are compiled, so a
// tier already on disk stops firing at the next reload instead of at the next
// weekly update.
//
// A rule belongs here only when its condition -- not merely its subject -- is
// unsound, and only when CSM detects the same technique itself. Suppressing a
// rule is never a substitute for detection: pair every entry with a rule in
// configs/malware.yar.
var suppressedRuleNames = []string{
	// Detects HTML smuggling by requiring exactly one "payload marker", but the
	// marker set mixes base64 file headers with the generic `.charCodeAt(i)^`
	// XOR idiom. Any minified bundle that offers a client-side download and
	// hashes a string satisfies it with nothing smuggled, which reported stock
	// analytics plugins and cached page assets as malware delivery.
	// Replaced by html_smuggling_payload, which requires the encoded header.
	"ELCEEF_HTML_Smuggling_A",
}

// SuppressedRuleNames returns the built-in rule suppressions.
func SuppressedRuleNames() []string {
	out := make([]string, len(suppressedRuleNames))
	copy(out, suppressedRuleNames)
	return out
}

// StripRules removes the named rules, bodies included, from YARA source text.
// Unknown names are ignored so a suppression list may name rules that a given
// tier does not ship.
func StripRules(content []byte, names []string) []byte {
	if len(names) == 0 {
		return content
	}

	drop := make(map[string]bool, len(names))
	for _, name := range names {
		if name != "" {
			drop[name] = true
		}
	}
	if len(drop) == 0 {
		return content
	}

	lines := strings.Split(string(content), "\n")
	result := make([]string, 0, len(lines))
	skipping := false
	sawOpen := false
	braceDepth := 0

	countBraces := func(s string) {
		for _, ch := range s {
			switch ch {
			case '{':
				braceDepth++
				sawOpen = true
			case '}':
				braceDepth--
			}
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !skipping {
			name := RuleNameFromLine(trimmed)
			if name == "" || !drop[name] {
				result = append(result, line)
				continue
			}
			skipping = true
			sawOpen = false
			braceDepth = 0
		}

		countBraces(trimmed)
		// YARA Forge writes the rule header and its opening brace on separate
		// lines. Ending the skip on depth<=0 before the body ever opened left
		// the body behind and broke compilation of the whole tier.
		if sawOpen && braceDepth <= 0 {
			skipping = false
			sawOpen = false
			braceDepth = 0
		}
	}

	return []byte(strings.Join(result, "\n"))
}

// RuleNameFromLine returns the rule name declared on a source line, or "" when
// the line does not open a rule.
func RuleNameFromLine(line string) string {
	s := strings.TrimPrefix(line, "private ")
	if !strings.HasPrefix(s, "rule ") {
		return ""
	}
	s = s[5:]
	for i, ch := range s {
		if ch == ' ' || ch == '\t' || ch == ':' || ch == '{' {
			return s[:i]
		}
	}
	return s
}
