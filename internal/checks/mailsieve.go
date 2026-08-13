package checks

import (
	"strings"
)

// Dovecot/Sieve exfiltration detector.
//
// cPanel webmail (Roundcube) stores per-mailbox Sieve scripts at
// /home/<user>/mail/<domain>/<localpart>/sieve/*.sieve, with the active script
// pointed to by .dovecot.sieve in the mailbox root. A compromised webmail
// account is commonly weaponised with a Sieve rule that redirects every message
// to an external dropbox while keeping a local copy, so the victim never
// notices the interception (business email compromise). Unlike the Exim filter
// path, Sieve is what actually executes for webmail-managed rules, so an
// exfil-only Exim audit misses it entirely.
//
// Sieve is a different grammar from Exim's filter language, so it has its own
// tokenizer and parser here, but it lowers into the same filterRule model the
// Exim scorer already understands (scoreFilterRules): a `redirect` becomes a
// deliver, `:copy` maps to Exim's `unseen` (deliver externally while the
// implicit keep preserves a local copy), `keep`/`fileinto` become a local
// save, and `discard` becomes a /dev/null save. This keeps stealth scoring,
// deduplication, suppression, and reasons identical across both mail-filter
// mechanisms.

type sieveTokenKind int

const (
	sieveWord sieveTokenKind = iota
	sieveString
	sieveTag // :copy, :contains, ...
	sievePunct
)

type sieveToken struct {
	text string
	kind sieveTokenKind
}

// tokenizeSieve splits Sieve source into tokens. Quoted strings (with \" and \\
// escapes) become a single string token; tags (:copy) become tag tokens;
// braces, brackets, parens, commas and semicolons are punctuation; line (#) and
// block (/* */) comments are dropped.
func tokenizeSieve(s string) []sieveToken {
	var toks []sieveToken
	runes := []rune(s)
	i := 0
	for i < len(runes) {
		c := runes[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '#':
			for i < len(runes) && runes[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(runes) && runes[i+1] == '*':
			i += 2
			for i+1 < len(runes) && (runes[i] != '*' || runes[i+1] != '/') {
				i++
			}
			i += 2
			if i > len(runes) {
				i = len(runes)
			}
		case c == '"':
			i++
			var b strings.Builder
			for i < len(runes) && runes[i] != '"' {
				if runes[i] == '\\' && i+1 < len(runes) {
					i++
				}
				b.WriteRune(runes[i])
				i++
			}
			if i < len(runes) {
				i++ // closing quote
			}
			toks = append(toks, sieveToken{text: b.String(), kind: sieveString})
		case c == '{' || c == '}' || c == '[' || c == ']' || c == '(' || c == ')' || c == ',' || c == ';':
			toks = append(toks, sieveToken{text: string(c), kind: sievePunct})
			i++
		case c == ':':
			start := i
			i++
			for i < len(runes) && isSieveIdentRune(runes[i]) {
				i++
			}
			toks = append(toks, sieveToken{text: string(runes[start:i]), kind: sieveTag})
		default:
			start := i
			for i < len(runes) && isSieveIdentRune(runes[i]) {
				i++
			}
			if i == start {
				// Unknown punctuation (e.g. a stray operator); skip one rune so
				// the tokenizer always makes progress on hostile input.
				i++
				continue
			}
			toks = append(toks, sieveToken{text: string(runes[start:i]), kind: sieveWord})
		}
	}
	return toks
}

func isSieveIdentRune(r rune) bool {
	return r == '_' || r == '.' || r == '-' ||
		(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func isSievePunct(t sieveToken, text string) bool {
	return t.kind == sievePunct && t.text == text
}

var sieveActions = map[string]bool{
	"redirect": true,
	"keep":     true,
	"fileinto": true,
	"discard":  true,
}

type sieveNode struct {
	rule   filterRule
	parent *sieveNode
}

// parseSieveFilter parses Sieve source into the flat filterRule list the Exim
// scorer consumes: one rule per if/elsif/else branch plus the unconditional top
// level, with ancestor actions folded into each branch so a keep in an outer
// block still pairs with a redirect in an inner branch.
func parseSieveFilter(content string) []filterRule {
	toks := tokenizeSieve(content)

	top := &sieveNode{rule: filterRule{matchesAll: true}}
	stack := []*sieveNode{top}
	nodes := []*sieveNode{top}

	i := 0
	for i < len(toks) {
		t := toks[i]
		if isSievePunct(t, "}") {
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			i++
			continue
		}
		if t.kind == sieveWord && (strings.EqualFold(t.text, "if") || strings.EqualFold(t.text, "elsif") || strings.EqualFold(t.text, "else")) {
			isElse := strings.EqualFold(t.text, "else")
			i++
			condStart := i
			for i < len(toks) && !isSievePunct(toks[i], "{") {
				i++
			}
			matchesAll := false
			if !isElse {
				matchesAll = sieveTestMatchesAll(toks[condStart:i])
			}
			if i < len(toks) {
				i++ // consume "{"
			}
			n := &sieveNode{rule: filterRule{matchesAll: matchesAll}, parent: stack[len(stack)-1]}
			nodes = append(nodes, n)
			stack = append(stack, n)
			continue
		}
		if t.kind == sieveWord && sieveActions[strings.ToLower(t.text)] {
			verb := strings.ToLower(t.text)
			i++
			var args []sieveToken
			for i < len(toks) && !isSievePunct(toks[i], ";") {
				if isSievePunct(toks[i], "{") || isSievePunct(toks[i], "}") {
					break
				}
				args = append(args, toks[i])
				i++
			}
			if i < len(toks) && isSievePunct(toks[i], ";") {
				i++
			}
			if act, ok := sieveActionToFilter(verb, args); ok {
				cur := stack[len(stack)-1]
				cur.rule.actions = append(cur.rule.actions, act)
			}
			continue
		}
		i++
	}

	out := make([]filterRule, 0, len(nodes))
	for _, n := range nodes {
		if len(n.rule.actions) > 0 {
			out = append(out, flattenSieveNode(n))
		}
	}
	return out
}

// sieveActionToFilter lowers one Sieve action into the Exim filterAction the
// scorer understands. Returns ok=false for actions that carry no exfil signal.
func sieveActionToFilter(verb string, args []sieveToken) (filterAction, bool) {
	switch verb {
	case "redirect":
		dest := lastSieveString(args)
		if dest == "" {
			return filterAction{}, false
		}
		// :copy keeps the implicit local copy alongside the forward -- the same
		// stealth signal as Exim's `unseen`.
		return filterAction{verb: "deliver", arg: dest, unseen: sieveHasTag(args, ":copy")}, true
	case "fileinto":
		dest := lastSieveString(args)
		if dest == "" {
			dest = "INBOX"
		}
		return filterAction{verb: "save", arg: dest}, true
	case "keep":
		return filterAction{verb: "save", arg: "$home/mail/INBOX"}, true
	case "discard":
		return filterAction{verb: "save", arg: "/dev/null"}, true
	}
	return filterAction{}, false
}

func lastSieveString(args []sieveToken) string {
	for i := len(args) - 1; i >= 0; i-- {
		if args[i].kind == sieveString {
			return args[i].text
		}
	}
	return ""
}

func sieveHasTag(args []sieveToken, tag string) bool {
	for _, a := range args {
		if a.kind == sieveTag && strings.EqualFold(a.text, tag) {
			return true
		}
	}
	return false
}

func flattenSieveNode(node *sieveNode) filterRule {
	var chain []*sieveNode
	for n := node; n != nil; n = n.parent {
		chain = append(chain, n)
	}
	out := filterRule{matchesAll: true}
	for i := len(chain) - 1; i >= 0; i-- {
		r := chain[i].rule
		if !r.matchesAll {
			out.matchesAll = false
		}
		out.actions = append(out.actions, r.actions...)
	}
	return out
}

// sieveTestMatchesAll reports whether a Sieve test fires on effectively all
// mail: the literal `true`, an anyof containing a match-all term, or an
// address/header comparison that is true for every normal email address.
func sieveTestMatchesAll(test []sieveToken) bool {
	hasNot := false
	hasTrue := false
	for _, t := range test {
		if t.kind == sieveWord {
			switch strings.ToLower(t.text) {
			case "not":
				hasNot = true
			case "true":
				hasTrue = true
			}
		}
	}
	if hasNot {
		return false
	}
	if hasTrue {
		return true
	}
	// address/header :contains "@" (or :matches "*") matches every address.
	hasAddressTest := false
	for _, t := range test {
		if t.kind == sieveWord {
			switch strings.ToLower(t.text) {
			case "address", "header":
				hasAddressTest = true
			}
		}
	}
	if !hasAddressTest {
		return false
	}
	// In `header :contains "from" "@"` the match key is the last string operand
	// (the header/address name comes first). A key of "@" matches every address.
	val := lastSieveString(test)
	if val == "" {
		return false
	}
	for _, t := range test {
		if t.kind != sieveTag {
			continue
		}
		switch strings.ToLower(t.text) {
		case ":contains":
			if val == "@" {
				return true
			}
		case ":matches":
			if val == "*" || val == "*@*" {
				return true
			}
		case ":is":
			if val == "*@*" {
				return true
			}
		}
	}
	return false
}

// mailboxFromSievePath derives the mailbox from a sieve script path of the form
// /home/<user>/mail/<domain>/<localpart>/... .
func mailboxFromSievePath(path string) filterMailbox {
	parts := strings.Split(path, "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "mail" && parts[i+1] != "" && parts[i+2] != "" {
			return filterMailbox{localPart: parts[i+2], domain: parts[i+1]}
		}
	}
	return filterMailbox{localPart: "*", domain: ""}
}
