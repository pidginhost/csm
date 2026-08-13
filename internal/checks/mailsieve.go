package checks

import (
	"net/mail"
	"sort"
	"strconv"
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
// save, and `discard` becomes a /dev/null save. Stealth scoring and reasons
// therefore stay aligned across both mechanisms; an exact KnownForwarders
// entry may additionally acknowledge Roundcube's ordinary :copy forwards.

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
		case isSieveTextLiteralStart(runes, i):
			var text string
			text, i = consumeSieveTextLiteral(runes, i)
			toks = append(toks, sieveToken{text: decodeSieveEncodedCharacters(text), kind: sieveString})
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
			toks = append(toks, sieveToken{text: decodeSieveEncodedCharacters(b.String()), kind: sieveString})
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

func isSieveTextLiteralStart(runes []rune, start int) bool {
	const prefix = "text:"
	if len(runes)-start < len(prefix) {
		return false
	}
	for i, want := range prefix {
		got := runes[start+i]
		if got >= 'A' && got <= 'Z' {
			got += 'a' - 'A'
		}
		if got != want {
			return false
		}
	}
	next := start + len(prefix)
	return next == len(runes) || runes[next] == ' ' || runes[next] == '\t' ||
		runes[next] == '\r' || runes[next] == '\n' || runes[next] == '#'
}

// consumeSieveTextLiteral consumes Sieve's text: multi-line string form. Its
// contents must stay opaque to the parser: prose in a vacation response can
// legitimately contain text such as `redirect "address";` without being an
// executable action. Unterminated literals consume the rest of the input.
func consumeSieveTextLiteral(runes []rune, start int) (string, int) {
	i := start + len("text:")
	for i < len(runes) && runes[i] != '\n' {
		i++
	}
	if i == len(runes) {
		return "", i
	}
	i++

	var b strings.Builder
	for i < len(runes) {
		lineStart := i
		for i < len(runes) && runes[i] != '\n' {
			i++
		}
		lineEnd := i
		if lineEnd > lineStart && runes[lineEnd-1] == '\r' {
			lineEnd--
		}
		line := runes[lineStart:lineEnd]
		if len(line) == 1 && line[0] == '.' {
			if i < len(runes) {
				i++
			}
			return b.String(), i
		}
		if len(line) >= 2 && line[0] == '.' && line[1] == '.' {
			line = line[1:]
		}
		b.WriteString(string(line))
		if i < len(runes) {
			b.WriteByte('\n')
			i++
		}
	}
	return b.String(), i
}

// decodeSieveEncodedCharacters handles the standard encoded-character
// extension. Without this normalization, `${hex:40}` can hide the @ in a
// redirect destination from the external-address scorer.
func decodeSieveEncodedCharacters(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '$' || i+2 >= len(s) || s[i+1] != '{' {
			out.WriteByte(s[i])
			i++
			continue
		}
		endRel := strings.IndexByte(s[i+2:], '}')
		if endRel < 0 {
			out.WriteString(s[i:])
			break
		}
		end := i + 2 + endRel
		body := s[i+2 : end]
		colon := strings.IndexByte(body, ':')
		if colon < 0 {
			out.WriteByte(s[i])
			i++
			continue
		}
		decoded, ok := decodeSieveCharacterSequence(strings.ToLower(strings.TrimSpace(body[:colon])), body[colon+1:])
		if !ok {
			out.WriteString(s[i : end+1])
		} else {
			out.WriteString(decoded)
		}
		i = end + 1
	}
	return out.String()
}

func decodeSieveCharacterSequence(kind, payload string) (string, bool) {
	fields := strings.Fields(payload)
	if len(fields) == 0 {
		return "", false
	}
	var out strings.Builder
	for _, field := range fields {
		if !isSieveHex(field) {
			return "", false
		}
		switch kind {
		case "hex":
			if len(field) > 2 {
				return "", false
			}
			value, err := strconv.ParseUint(field, 16, 8)
			if err != nil {
				return "", false
			}
			out.WriteByte(byte(value))
		case "unicode":
			if len(field) > 6 {
				return "", false
			}
			value, err := strconv.ParseUint(field, 16, 32)
			if err != nil || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff) {
				return "", false
			}
			out.WriteRune(rune(value))
		default:
			return "", false
		}
	}
	return out.String(), true
}

func isSieveHex(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
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
	"stop":     true,
	"return":   true,
}

type sieveOrderedAction struct {
	position int
	action   filterAction
}

type sieveBranchChain struct {
	parent           *sieveNode
	allPreviousNever bool
	previousAlways   bool
	continuePossible bool
	stopPossible     bool
}

type sieveNode struct {
	rule      filterRule
	parent    *sieveNode
	branch    *sieveBranchChain
	actions   []sieveOrderedAction
	reachable bool
	flow      sieveTruth
}

func (c *sieveBranchChain) recordBranch(flow sieveTruth) {
	c.continuePossible = c.continuePossible || flow != sieveNever
	c.stopPossible = c.stopPossible || flow != sieveAlways
}

func finishSieveBranchChain(c *sieveBranchChain) {
	if c == nil || c.parent == nil {
		return
	}
	// With no final else, messages that match none of the branch tests flow
	// through the chain unchanged.
	if !c.previousAlways {
		c.continuePossible = true
	}
	continuation := sieveConditional
	switch {
	case c.continuePossible && !c.stopPossible:
		continuation = sieveAlways
	case !c.continuePossible && c.stopPossible:
		continuation = sieveNever
	}
	c.parent.flow = composeSieveFlow(c.parent.flow, continuation)
}

func composeSieveFlow(first, second sieveTruth) sieveTruth {
	if first == sieveNever || second == sieveNever {
		return sieveNever
	}
	if first == sieveAlways {
		return second
	}
	return sieveConditional
}

// parseSieveFilter parses Sieve source into the flat filterRule list the Exim
// scorer consumes: one rule per if/elsif/else branch plus the unconditional top
// level, with ancestor actions folded into each branch so a keep in an outer
// block still pairs with a redirect in an inner branch.
func parseSieveFilter(content string) []filterRule {
	toks := tokenizeSieve(content)

	top := &sieveNode{rule: filterRule{matchesAll: true}, reachable: true, flow: sieveAlways}
	stack := []*sieveNode{top}
	nodes := []*sieveNode{top}
	var pendingChain *sieveBranchChain

	i := 0
	for i < len(toks) {
		t := toks[i]
		continuesBranch := pendingChain != nil && pendingChain.parent == stack[len(stack)-1] &&
			t.kind == sieveWord && (strings.EqualFold(t.text, "elsif") || strings.EqualFold(t.text, "else"))
		if pendingChain != nil && !continuesBranch {
			finishSieveBranchChain(pendingChain)
			pendingChain = nil
		}
		if isSievePunct(t, "}") {
			if len(stack) > 1 {
				closed := stack[len(stack)-1]
				if closed.reachable {
					closed.branch.recordBranch(closed.flow)
				}
				pendingChain = closed.branch
				stack = stack[:len(stack)-1]
			} else {
				pendingChain = nil
			}
			i++
			continue
		}
		if t.kind == sieveWord && (strings.EqualFold(t.text, "if") || strings.EqualFold(t.text, "elsif") || strings.EqualFold(t.text, "else")) {
			keyword := strings.ToLower(t.text)
			isElse := keyword == "else"
			parent := stack[len(stack)-1]
			chain := pendingChain
			if keyword == "if" || chain == nil || chain.parent != parent {
				chain = &sieveBranchChain{parent: parent, allPreviousNever: keyword == "if"}
			}
			pendingChain = nil
			i++
			condStart := i
			for i < len(toks) && !isSievePunct(toks[i], "{") {
				i++
			}

			branchReachable := !chain.previousAlways
			branchMatchesAll := chain.allPreviousNever
			if isElse {
				chain.previousAlways = true
				chain.allPreviousNever = false
			} else {
				truth := sieveTestTruthValue(toks[condStart:i])
				branchReachable = branchReachable && truth != sieveNever
				branchMatchesAll = branchMatchesAll && truth == sieveAlways
				chain.previousAlways = chain.previousAlways || truth == sieveAlways
				chain.allPreviousNever = chain.allPreviousNever && truth == sieveNever
			}
			if i < len(toks) {
				i++ // consume "{"
			}
			n := &sieveNode{
				rule:      filterRule{matchesAll: parent.rule.matchesAll && parent.flow == sieveAlways && branchMatchesAll},
				parent:    parent,
				branch:    chain,
				reachable: parent.reachable && parent.flow != sieveNever && branchReachable,
				flow:      sieveAlways,
			}
			nodes = append(nodes, n)
			stack = append(stack, n)
			continue
		}
		pendingChain = nil
		if t.kind == sieveWord && sieveActions[strings.ToLower(t.text)] {
			verb := strings.ToLower(t.text)
			position := i
			i++
			var args []sieveToken
			for i < len(toks) && !isSievePunct(toks[i], ";") {
				if isSievePunct(toks[i], "{") || isSievePunct(toks[i], "}") {
					break
				}
				args = append(args, toks[i])
				i++
			}
			if i >= len(toks) || !isSievePunct(toks[i], ";") {
				continue
			}
			i++
			cur := stack[len(stack)-1]
			if cur.flow == sieveNever {
				continue
			}
			if act, ok := sieveActionToFilter(verb, args); ok {
				act.matchesAll = cur.rule.matchesAll && cur.flow == sieveAlways
				cur.actions = append(cur.actions, sieveOrderedAction{position: position, action: act})
				if act.verb == "finish" {
					cur.flow = sieveNever
				}
			}
			continue
		}
		i++
	}
	finishSieveBranchChain(pendingChain)

	out := make([]filterRule, 0, len(nodes))
	for _, n := range nodes {
		if n.reachable && len(n.actions) > 0 {
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
		if address, err := mail.ParseAddress(dest); err == nil {
			dest = address.Address
		}
		// :copy keeps the implicit local copy alongside the forward -- the same
		// stealth signal as Exim's `unseen`.
		copyRedirect := sieveHasTag(args, ":copy")
		return filterAction{
			verb:              "deliver",
			arg:               dest,
			unseen:            copyRedirect,
			knownSuppressible: copyRedirect,
		}, true
	case "fileinto":
		dest := lastSieveString(args)
		if dest == "" {
			return filterAction{}, false
		}
		return filterAction{verb: "save", arg: dest}, true
	case "keep":
		return filterAction{verb: "save", arg: "$home/mail/INBOX"}, true
	case "discard":
		return filterAction{verb: "save", arg: "/dev/null"}, true
	case "stop", "return":
		return filterAction{verb: "finish"}, true
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
	var actions []sieveOrderedAction
	for _, n := range chain {
		actions = append(actions, n.actions...)
	}
	sort.SliceStable(actions, func(i, j int) bool {
		return actions[i].position < actions[j].position
	})

	// Sieve actions carry their own match-all reachability because a prior
	// conditional stop can make later actions selective within the same scope.
	// Exim rules retain their rule-wide matchesAll representation.
	out := filterRule{}
	for _, ordered := range actions {
		out.actions = append(out.actions, ordered.action)
		if ordered.action.verb == "finish" {
			break
		}
	}
	return out
}

type sieveTruth int

const (
	sieveNever sieveTruth = iota
	sieveConditional
	sieveAlways
)

// sieveTestMatchesAll reports whether a Sieve test fires on effectively all
// mail. It evaluates anyof/allof structure instead of combining unrelated
// operands from different subtests, and stays conservative on malformed or
// excessively nested input.
func sieveTestMatchesAll(test []sieveToken) bool {
	return sieveTestTruthValue(test) == sieveAlways
}

func sieveTestTruthValue(test []sieveToken) sieveTruth {
	return sieveExpressionTruth(test, 0)
}

func sieveExpressionTruth(test []sieveToken, depth int) sieveTruth {
	const maxSieveTestDepth = 256
	if depth >= maxSieveTestDepth {
		return sieveConditional
	}
	test, ok := trimSieveOuterParens(test)
	if !ok || len(test) == 0 || test[0].kind != sieveWord {
		return sieveConditional
	}

	keyword := strings.ToLower(test[0].text)
	switch keyword {
	case "true":
		if len(test) == 1 {
			return sieveAlways
		}
	case "false":
		if len(test) == 1 {
			return sieveNever
		}
	case "not":
		inner := sieveExpressionTruth(test[1:], depth+1)
		switch inner {
		case sieveAlways:
			return sieveNever
		case sieveNever:
			return sieveAlways
		default:
			return sieveConditional
		}
	case "anyof", "allof":
		parts, ok := sieveCallArguments(test[1:])
		if !ok || len(parts) == 0 {
			return sieveConditional
		}
		if keyword == "anyof" {
			allNever := true
			for _, part := range parts {
				truth := sieveExpressionTruth(part, depth+1)
				if truth == sieveAlways {
					return sieveAlways
				}
				allNever = allNever && truth == sieveNever
			}
			if allNever {
				return sieveNever
			}
			return sieveConditional
		}

		allAlways := true
		for _, part := range parts {
			truth := sieveExpressionTruth(part, depth+1)
			if truth == sieveNever {
				return sieveNever
			}
			allAlways = allAlways && truth == sieveAlways
		}
		if allAlways {
			return sieveAlways
		}
		return sieveConditional
	case "address", "header":
		if sieveAddressTestMatchesAll(test) {
			return sieveAlways
		}
	}
	return sieveConditional
}

func trimSieveOuterParens(test []sieveToken) ([]sieveToken, bool) {
	matchingClose := make([]int, len(test))
	for i := range matchingClose {
		matchingClose[i] = -1
	}
	var stack []int
	for i, tok := range test {
		switch {
		case isSievePunct(tok, "("):
			stack = append(stack, i)
		case isSievePunct(tok, ")"):
			if len(stack) == 0 {
				return nil, false
			}
			open := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			matchingClose[open] = i
		}
	}
	if len(stack) != 0 {
		return nil, false
	}
	left, right := 0, len(test)-1
	for left < right && isSievePunct(test[left], "(") && matchingClose[left] == right {
		left++
		right--
	}
	return test[left : right+1], true
}

func sieveCallArguments(test []sieveToken) ([][]sieveToken, bool) {
	if len(test) < 2 || !isSievePunct(test[0], "(") || !isSievePunct(test[len(test)-1], ")") {
		return nil, false
	}
	return splitSieveTopLevel(test[1:len(test)-1], ",")
}

func splitSieveTopLevel(test []sieveToken, separator string) ([][]sieveToken, bool) {
	var parts [][]sieveToken
	start := 0
	parenDepth := 0
	listDepth := 0
	for i, tok := range test {
		switch {
		case isSievePunct(tok, "("):
			parenDepth++
		case isSievePunct(tok, ")"):
			parenDepth--
		case isSievePunct(tok, "["):
			listDepth++
		case isSievePunct(tok, "]"):
			listDepth--
		case parenDepth == 0 && listDepth == 0 && isSievePunct(tok, separator):
			if start == i {
				return nil, false
			}
			parts = append(parts, test[start:i])
			start = i + 1
		}
		if parenDepth < 0 || listDepth < 0 {
			return nil, false
		}
	}
	if parenDepth != 0 || listDepth != 0 || start >= len(test) {
		return nil, false
	}
	parts = append(parts, test[start:])
	return parts, true
}

func sieveAddressTestMatchesAll(test []sieveToken) bool {
	testKind := strings.ToLower(test[0].text)
	matchType := ""
	addressPart := ":all"
	addressPartSeen := false
	comparatorSeen := false
	var operands [][]string
	for i := 1; i < len(test); {
		tok := test[i]
		switch {
		case tok.kind == sieveTag:
			tag := strings.ToLower(tok.text)
			switch tag {
			case ":contains", ":matches", ":is":
				if matchType != "" {
					return false
				}
				matchType = tag
			case ":all", ":localpart", ":domain", ":detail":
				if testKind != "address" {
					return false
				}
				if addressPartSeen {
					return false
				}
				addressPartSeen = true
				addressPart = tag
			case ":comparator":
				if comparatorSeen {
					return false
				}
				comparatorSeen = true
				i++
				if i >= len(test) || test[i].kind != sieveString {
					return false
				}
			default:
				// Extensions such as :index/:last and :mime/:anychild alter
				// which header occurrence or MIME part is examined. Even From
				// is not guaranteed to exist in that narrowed scope, so it is
				// unsafe to classify the test as match-all. Unknown modifiers
				// stay conservative for the same reason.
				return false
			}
			i++
		case tok.kind == sieveString:
			operands = append(operands, []string{tok.text})
			i++
		case isSievePunct(tok, "["):
			var values []string
			i++
			for i < len(test) && !isSievePunct(test[i], "]") {
				if test[i].kind == sieveString {
					values = append(values, test[i].text)
				} else if !isSievePunct(test[i], ",") {
					return false
				}
				i++
			}
			if i >= len(test) || len(values) == 0 {
				return false
			}
			i++
			operands = append(operands, values)
		default:
			return false
		}
	}
	if len(operands) != 2 {
		return false
	}

	// The first string-list is the header name and the final string-list is
	// the match key. Only From is reliably present and address-bearing on every
	// normal message; Subject/To and arbitrary headers are not match-all.
	hasFrom := false
	for _, header := range operands[0] {
		if strings.EqualFold(strings.TrimSpace(header), "from") {
			hasFrom = true
			break
		}
	}
	if !hasFrom {
		return false
	}
	for _, key := range operands[1] {
		switch matchType {
		case ":contains":
			if key == "" || (addressPart == ":all" && key == "@") {
				return true
			}
		case ":matches":
			if key == "*" || (addressPart == ":all" && key == "*@*") {
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
	for i := 0; i+4 < len(parts); i++ {
		if parts[i] == "home" && parts[i+1] != "" && parts[i+2] == "mail" && parts[i+3] != "" && parts[i+4] != "" {
			return filterMailbox{localPart: parts[i+4], domain: parts[i+3]}
		}
	}
	return filterMailbox{localPart: "*", domain: ""}
}
