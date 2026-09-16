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

	// Detects a Windows IIS native-module family, but its condition is
	// `native_module_private and 2 of ($i*) or 5 of them`. The trailing arm
	// drops the native-module guard, so five generic strings decide the
	// match -- and four of them are crawler user agents (Baiduspider,
	// 360Spider, Sogou, YisouSpider) that any PHP bot-filter table lists
	// alongside HTTP_X_FORWARDED_FOR. Stock analytics plugins matched.
	// Replaced by seo_cloak_group14_ioc, which binds the campaign markers to
	// native-module or campaign-infrastructure context and drops the user-agent
	// arm.
	"ESET_IIS_Group14",
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
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
			drop[name] = true
		}
	}
	if len(drop) == 0 {
		return content
	}

	var result []byte
	kept := 0
	for _, rule := range sourceRules(content) {
		if drop[strings.ToLower(rule.name)] {
			result = append(result, content[kept:rule.start]...)
			kept = rule.end
		}
	}
	if kept == 0 {
		return content
	}
	return append(result, content[kept:]...)
}

type sourceRule struct {
	name       string
	start, end int
}

// RuleNames returns declarations outside comments and literals. Validation
// uses the same boundaries as stripping, including modifiers and compact files.
func RuleNames(content []byte) []string {
	var names []string
	for _, rule := range sourceRules(content) {
		names = append(names, rule.name)
	}
	return names
}

// sourceRules locates complete rule bodies without interpreting conditions.
// Counting source braces or removing whole lines can silently erase a neighbor:
// braces also occur in strings, comments, regexes and hex patterns.
func sourceRules(content []byte) []sourceRule {
	var rules []sourceRule
	start := -1
	for pos := 0; pos < len(content); {
		token, from, end := yaraToken(content, pos)
		pos = end
		if token == "private" || token == "global" {
			if start < 0 {
				start = from
			}
			continue
		}
		if token != "rule" {
			start = -1
			continue
		}
		if start < 0 {
			start = from
		}
		name, _, next := yaraToken(content, pos)
		pos = next
		if !yaraIdentifier(name) {
			break
		}
		token, _, pos = yaraToken(content, pos)
		if token == ":" {
			token, _, pos = yaraToken(content, pos)
			if !yaraIdentifier(token) {
				break
			}
			for yaraIdentifier(token) {
				token, _, pos = yaraToken(content, pos)
			}
		}
		if token != "{" {
			break
		}
		depth := 1
		for pos < len(content) && depth > 0 {
			token, _, pos = yaraToken(content, pos)
			switch token {
			case "{":
				depth++
			case "}":
				depth--
			}
		}
		// Leave malformed source intact so compilation still reports it.
		if depth != 0 {
			break
		}
		rules = append(rules, sourceRule{name: name, start: start, end: pos})
		start = -1
	}
	return rules
}

// yaraToken skips trivia and consumes quoted/regex literals as single tokens.
// YARA uses backslash for division, so slash always starts a regex or comment.
func yaraToken(src []byte, pos int) (token string, start, end int) {
	for pos < len(src) {
		switch src[pos] {
		case ' ', '\t', '\r', '\n', '\f', '\v':
			pos++
			continue
		case '/':
			if pos+1 < len(src) && src[pos+1] == '/' {
				pos += 2
				for pos < len(src) && src[pos] != '\n' && src[pos] != '\r' {
					pos++
				}
				continue
			}
			if pos+1 < len(src) && src[pos+1] == '*' {
				pos += 2
				for pos+1 < len(src) && (src[pos] != '*' || src[pos+1] != '/') {
					pos++
				}
				pos = min(pos+2, len(src))
				continue
			}
		}
		break
	}
	start = pos
	if pos == len(src) {
		return "", pos, pos
	}
	ch := src[pos]
	pos++
	if ch == '"' || ch == '/' {
		inClass := false
		for pos < len(src) {
			c := src[pos]
			pos++
			if c == '\\' {
				pos = min(pos+1, len(src))
				continue
			}
			if ch == '/' {
				switch c {
				case '[':
					inClass = true
				case ']':
					inClass = false
				}
			}
			if c == ch && !inClass {
				break
			}
		}
		return string(src[start:pos]), start, pos
	}
	if yaraIdent(ch) {
		for pos < len(src) && yaraIdent(src[pos]) {
			pos++
		}
	}
	return string(src[start:pos]), start, pos
}

func yaraIdent(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_'
}

func yaraIdentifier(token string) bool {
	// A following declaration must not become part of a malformed tag list.
	if token == "rule" || token == "private" || token == "global" {
		return false
	}
	if token == "" || token[0] >= '0' && token[0] <= '9' {
		return false
	}
	for i := range len(token) {
		if !yaraIdent(token[i]) {
			return false
		}
	}
	return true
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
