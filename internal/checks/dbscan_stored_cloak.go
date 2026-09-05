package checks

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// Cloak logic stored in the database.
//
// A cloak has to decide what to serve on every request, which means the page
// must not be cached. Stored code that disables caching and, in the same
// snippet, looks for a search-engine crawler is serving one page to the index
// and another to visitors.
//
// Neither half is evidence on its own, which is why both are required: caching
// plugins invoke cache helpers from their own files as a matter of course, and
// reading the user agent is ordinary. It is a stored snippet doing both that
// has no innocent reading -- the snippet is not the caching plugin, and it has
// no reason to care whether the visitor is Googlebot.

// crawlerUserAgent matches the crawlers a doorway kit cares about. The list is
// the set worth cloaking for: the engines that index and rank, plus the SEO
// crawlers kits hide from to stay out of backlink reports.
var crawlerUserAgent = regexp.MustCompile(
	`(?i)\b(googlebot|bingbot|msnbot|yandex(?:bot)?|baiduspider|duckduckbot|slurp|` +
		`applebot|sogou|exabot|facebot|ia_archiver|ahrefsbot|semrushbot|mj12bot|dotbot|petalbot|` +
		`oai-searchbot|claude-searchbot)\b`)

const (
	// The detector only reports known signals, but explicit caps keep finding
	// text and derived-literal work bounded if those vocabularies grow.
	maxStoredCloakMatches      = 64
	maxStoredCloakDetailNames  = 8
	maxStoredCloakDerivedBytes = maxStoredCodeBytes
	maxStoredScalarParens      = 32
)

// storedCloakComponents returns the cache-defeat and crawler-detection markers
// found in one stored snippet.
func storedCloakComponents(code []byte) (cacheDefeat, crawler []string) {
	php := stripPHPCommentsFromCode(string(code))
	// Heredoc and nowdoc bodies are string data. Keep them available to the
	// crawler-literal scan, but do not parse helper calls or $_SERVER accesses
	// written inside them as executable PHP.
	executablePHP := blankStoredPHPHeredocs(php)
	cacheDefeat = storedCacheDefeatSignals(executablePHP)
	if len(cacheDefeat) == 0 {
		return nil, nil
	}

	// A crawler name in documentation or output is not a visitor test. Require
	// the snippet to inspect the HTTP user agent, including a name assembled
	// from constant string operations.
	if !storedHasUserAgentInspection(executablePHP) {
		return cacheDefeat, nil
	}
	derived := storedCloakDerivedStrings(executablePHP)
	searchable := php + "\n" + derived
	crawler = appendCapturedNames(nil, make(map[string]bool), crawlerUserAgent,
		[]byte(searchable), strings.ToLower)
	return limitStoredCloakNames(cacheDefeat), limitStoredCloakNames(crawler)
}

// appendCapturedNames collects the first capture group of each match, so the
// finding names the constant or crawler rather than the surrounding syntax.
func appendCapturedNames(out []string, seen map[string]bool, re *regexp.Regexp, code []byte, canonical func(string) string) []string {
	for _, m := range re.FindAllSubmatch(code, maxStoredCloakMatches) {
		if len(m) < 2 {
			continue
		}
		name := canonical(strings.TrimSpace(string(m[1])))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func limitStoredCloakNames(names []string) []string {
	if len(names) > maxStoredCloakDetailNames {
		return names[:maxStoredCloakDetailNames]
	}
	return names
}

func blankStoredPHPHeredocs(code string) string {
	var out strings.Builder
	out.Grow(len(code))
	for i := 0; i < len(code); i++ {
		// A quoted string can contain text that looks like an unterminated
		// heredoc opener. Skip it whole so that text cannot blank executable
		// code after the closing quote.
		if isPHPQuote(code[i]) {
			end := skipPHPString(code, i)
			out.WriteString(code[i : end+1])
			i = end
			continue
		}
		if label, bodyStart, ok := phpHeredocOpen(code, i); ok {
			end := phpHeredocEnd(code, bodyStart, label)
			blankInlineHTML(&out, code[i:end])
			i = end - 1
			continue
		}
		out.WriteByte(code[i])
	}
	return out.String()
}

type storedPHPBool uint8

const (
	storedPHPBoolUnknown storedPHPBool = iota
	storedPHPBoolFalse
	storedPHPBoolTrue
)

type storedPHPBoolAssignment struct {
	pos   int
	value storedPHPBool
}

// storedCacheDefeatSignals recognises operations that stop the current request
// from being cached. Parsing real calls and assignments avoids treating a
// comment, string example, false DONOTCACHE value, or true WP_CACHE value as
// executable cache control.
func storedCacheDefeatSignals(code string) []string {
	seen := make(map[string]bool)
	var signals []string
	var assignments map[string][]storedPHPBoolAssignment
	boolValue := func(expr string, before int) storedPHPBool {
		value := storedPHPBoolExpression(expr, nil, before)
		if value != storedPHPBoolUnknown {
			return value
		}
		if _, ok := singlePHPVariableExpr(trimStoredPHPParens(strings.TrimSpace(expr))); !ok {
			return storedPHPBoolUnknown
		}
		if assignments == nil {
			assignments = storedPHPBoolAssignments(code)
		}
		return storedPHPBoolExpression(expr, assignments, before)
	}

	callNames := map[string]struct{}{
		"define":          {},
		"header":          {},
		"nocache_headers": {},
	}
	for searchFrom := 0; searchFrom < len(code); {
		callStart, openParen, closeParen, ok := nextStandalonePHPCall(code, searchFrom, callNames)
		if !ok {
			break
		}
		searchFrom = nextSearchOffset(closeParen, len(code))
		if closeParen >= len(code) || storedPHPCallIsNonGlobal(code, callStart) {
			continue
		}
		name := storedPHPCallName(code[callStart:openParen])
		args := phpCallArguments(code, openParen+1, closeParen)
		switch name {
		case "define":
			if len(args) < 2 {
				continue
			}
			constantName, ok := storedConstantStringExpression(args[0])
			if !ok {
				continue
			}
			constantName = strings.ToUpper(strings.TrimSpace(constantName))
			value := boolValue(args[1], callStart)
			switch constantName {
			case "DONOTCACHEPAGE":
				if value == storedPHPBoolTrue {
					signals = appendStoredCloakName(signals, seen, constantName)
				}
			case "WP_CACHE":
				if value == storedPHPBoolFalse {
					signals = appendStoredCloakName(signals, seen, constantName)
				}
			}
		case "header":
			if len(args) == 0 {
				continue
			}
			headerValue, ok := storedConstantStringExpression(args[0])
			if ok && storedLiteSpeedNoCacheHeader(headerValue) {
				signals = appendStoredCloakName(signals, seen, "X-LiteSpeed-Cache-Control")
			}
		case "nocache_headers":
			if len(args) == 0 {
				signals = appendStoredCloakName(signals, seen, "nocache_headers")
			}
		}
	}

	sort.Strings(signals)
	return limitStoredCloakNames(signals)
}

func appendStoredCloakName(out []string, seen map[string]bool, name string) []string {
	if name == "" || seen[name] {
		return out
	}
	seen[name] = true
	return append(out, name)
}

func storedPHPCallName(callPrefix string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(callPrefix), `\`))
}

func storedPHPCallIsNonGlobal(code string, callStart int) bool {
	i := callStart - 1
	for i >= 0 && isPHPSpace(code[i]) {
		i--
	}
	// PHP permits whitespace around member, static, and namespace operators.
	// Those calls do not invoke the WordPress/PHP global cache helpers.
	if i >= 0 && (code[i] == '>' || code[i] == ':' || code[i] == '\\') {
		return true
	}
	if i >= 0 && code[i] == '&' {
		i--
		for i >= 0 && isPHPSpace(code[i]) {
			i--
		}
	}
	end := i + 1
	for i >= 0 && isPHPIdentifierPart(code[i]) {
		i--
	}
	return strings.EqualFold(code[i+1:end], "function")
}

func storedLiteSpeedNoCacheHeader(value string) bool {
	name, directive, ok := strings.Cut(value, ":")
	if !ok || !strings.EqualFold(strings.TrimSpace(name), "X-LiteSpeed-Cache-Control") {
		return false
	}
	for _, item := range strings.Split(directive, ",") {
		if strings.EqualFold(strings.TrimSpace(item), "no-cache") {
			return true
		}
	}
	return false
}

func storedPHPBoolAssignments(code string) map[string][]storedPHPBoolAssignment {
	assignments := make(map[string][]storedPHPBoolAssignment)
	for i := 0; i < len(code); i++ {
		if isPHPQuote(code[i]) {
			i = skipPHPString(code, i)
			continue
		}
		if code[i] != '$' {
			continue
		}
		variable, next, ok := readPHPVariableName(code, i)
		if !ok {
			continue
		}
		operator := skipPHPWhitespace(code, next)
		opLen, direct, _, ok := phpAssignmentOperator(code, operator)
		if !ok {
			i = next - 1
			continue
		}
		exprStart := skipPHPWhitespace(code, operator+opLen)
		exprEnd := phpExpressionEnd(code, exprStart)
		value := storedPHPBoolUnknown
		if direct {
			value = storedPHPBoolExpression(code[exprStart:exprEnd], assignments, exprStart)
		}
		assignments[variable] = append(assignments[variable], storedPHPBoolAssignment{
			pos: exprEnd, value: value,
		})
		i = exprEnd - 1
	}
	return assignments
}

func storedPHPBoolExpression(expr string, assignments map[string][]storedPHPBoolAssignment, before int) storedPHPBool {
	expr = trimStoredPHPParens(strings.TrimSpace(expr))
	switch strings.ToLower(expr) {
	case "true":
		return storedPHPBoolTrue
	case "false", "null":
		return storedPHPBoolFalse
	}
	if value, ok := storedConstantStringExpression(expr); ok {
		if value == "" || value == "0" {
			return storedPHPBoolFalse
		}
		return storedPHPBoolTrue
	}
	if number, err := strconv.ParseFloat(expr, 64); err == nil {
		if number == 0 {
			return storedPHPBoolFalse
		}
		return storedPHPBoolTrue
	}
	variable, ok := singlePHPVariableExpr(expr)
	if !ok {
		return storedPHPBoolUnknown
	}
	values := assignments[variable]
	index := sort.Search(len(values), func(i int) bool {
		return values[i].pos > before
	})
	if index > 0 {
		return values[index-1].value
	}
	return storedPHPBoolUnknown
}

func trimStoredPHPParens(expr string) string {
	// Scalar expressions are attacker-controlled. Cap redundant-wrapper work so
	// deeply nested input cannot turn repeated matching scans quadratic.
	for depth := 0; depth < maxStoredScalarParens && len(expr) >= 2 && expr[0] == '(' && matchingParen(expr, 0) == len(expr)-1; depth++ {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}
	return expr
}

// storedCloakDerivedStrings evaluates only bounded, constant string operations
// commonly used to hide crawler literals. General PHP evaluation is outside
// this detector; literal XOR remains covered by the backdoor signature.
func storedCloakDerivedStrings(code string) string {
	var derived strings.Builder
	for i := 0; i < len(code) && derived.Len() < maxStoredCloakDerivedBytes; i++ {
		if !isPHPQuote(code[i]) {
			continue
		}
		closeQuote, closed := storedPHPStringClose(code, i)
		if !closed {
			break
		}
		dot := skipPHPWhitespace(code, closeQuote+1)
		if dot >= len(code) || code[dot] != '.' {
			i = closeQuote
			continue
		}
		nextOperand := skipPHPWhitespace(code, dot+1)
		if nextOperand >= len(code) || !isPHPQuote(code[nextOperand]) {
			i = closeQuote
			continue
		}
		value, end, parts, ok := storedConstantStringAt(code, i)
		if !ok {
			continue
		}
		if parts > 1 {
			appendStoredDerivedString(&derived, value)
		}
		i = end - 1
	}

	rot13 := map[string]struct{}{"str_rot13": {}}
	for searchFrom := 0; searchFrom < len(code) && derived.Len() < maxStoredCloakDerivedBytes; {
		callStart, openParen, closeParen, ok := nextStandalonePHPCall(code, searchFrom, rot13)
		if !ok {
			break
		}
		searchFrom = nextSearchOffset(closeParen, len(code))
		if closeParen >= len(code) || storedPHPCallIsNonGlobal(code, callStart) {
			continue
		}
		args := phpCallArguments(code, openParen+1, closeParen)
		if len(args) != 1 {
			continue
		}
		value, ok := storedConstantStringExpression(args[0])
		if ok {
			appendStoredDerivedString(&derived, storedROT13(value))
		}
	}
	return derived.String()
}

func appendStoredDerivedString(out *strings.Builder, value string) {
	remaining := maxStoredCloakDerivedBytes - out.Len()
	if remaining <= 1 {
		return
	}
	out.WriteByte('\n')
	remaining--
	if len(value) > remaining {
		value = value[:remaining]
	}
	out.WriteString(value)
}

func storedConstantStringExpression(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	value, end, _, ok := storedConstantStringAt(expr, 0)
	return value, ok && skipPHPWhitespace(expr, end) == len(expr)
}

func storedConstantStringAt(code string, start int) (string, int, int, bool) {
	if start >= len(code) || !isPHPQuote(code[start]) {
		return "", start, 0, false
	}
	var value strings.Builder
	parts := 0
	pos := start
	for {
		if pos >= len(code) || !isPHPQuote(code[pos]) {
			return "", start, 0, false
		}
		closeQuote, closed := storedPHPStringClose(code, pos)
		if !closed {
			return "", start, 0, false
		}
		if storedPHPStringInterpolates(code, pos, closeQuote) {
			return "", start, 0, false
		}
		value.WriteString(phpStringLiteralValue(code, pos, closeQuote))
		parts++
		next := skipPHPWhitespace(code, closeQuote+1)
		if next >= len(code) || code[next] != '.' {
			return value.String(), closeQuote + 1, parts, true
		}
		pos = skipPHPWhitespace(code, next+1)
		if pos >= len(code) || !isPHPQuote(code[pos]) {
			return value.String(), closeQuote + 1, parts, true
		}
	}
}

func storedPHPStringInterpolates(code string, start, end int) bool {
	if code[start] != '"' {
		return false
	}
	for i := start + 1; i < end; i++ {
		if code[i] == '\\' && i+1 < end {
			i++
			continue
		}
		if code[i] == '$' && i+1 < end && (code[i+1] == '{' || isPHPIdentifierStart(code[i+1])) {
			return true
		}
	}
	return false
}

func storedPHPStringClose(code string, start int) (int, bool) {
	quote := code[start]
	for i := start + 1; i < len(code); i++ {
		if code[i] == '\\' && i+1 < len(code) {
			i++
			continue
		}
		if code[i] == quote {
			return i, true
		}
	}
	return len(code), false
}

// storedHasUserAgentInspection requires an executable $_SERVER access instead
// of accepting HTTP_USER_AGENT in prose or another string literal. Constant
// string concatenation is enough to cover the common lightly-obfuscated key
// without following arbitrary attacker-controlled variables. Parsing just the
// supported scalar key avoids repeatedly searching nested, hostile brackets.
func storedHasUserAgentInspection(code string) bool {
	for i := 0; i < len(code); i++ {
		if isPHPQuote(code[i]) {
			i = skipPHPString(code, i)
			continue
		}
		if code[i] != '$' {
			continue
		}
		variable, next, ok := readPHPVariableName(code, i)
		if !ok || !strings.EqualFold(variable, "_SERVER") {
			continue
		}
		openBracket := skipPHPWhitespace(code, next)
		if openBracket >= len(code) || code[openBracket] != '[' {
			continue
		}
		keyStart := skipPHPWhitespace(code, openBracket+1)
		key, keyEnd, _, ok := storedConstantStringAt(code, keyStart)
		if !ok {
			continue
		}
		closeBracket := skipPHPWhitespace(code, keyEnd)
		if closeBracket < len(code) && code[closeBracket] == ']' &&
			strings.EqualFold(key, "HTTP_USER_AGENT") {
			return true
		}
	}
	return false
}

func storedROT13(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		default:
			return r
		}
	}, value)
}

// storedCloakFinding reports a stored snippet that both defeats caching and
// looks for a crawler, or nil when only one half is present.
func storedCloakFinding(user string, creds wpDBCreds, prefix string, row storedCodeRow) *alert.Finding {
	cacheDefeat, crawler := storedCloakComponents(row.code)
	return storedCloakFindingWithComponents(user, creds, prefix, row, cacheDefeat, crawler)
}

func storedCloakFindingWithComponents(user string, creds wpDBCreds, prefix string, row storedCodeRow, cacheDefeat, crawler []string) *alert.Finding {
	if len(cacheDefeat) == 0 || len(crawler) == 0 {
		return nil
	}

	// Only a published snippet runs. A draft still documents the intent.
	severity := alert.Warning
	if row.status == "publish" {
		severity = alert.High
	}

	return &alert.Finding{
		Severity: severity,
		Check:    "db_stored_cloak_logic",
		Message: fmt.Sprintf("Stored PHP snippet %s (%s) serves crawlers differently from visitors (account: %s)",
			row.id, row.status, user),
		Details: dbContentFindingDetails(creds, prefix,
			fmt.Sprintf("Snippet %s is stored in %sposts, so no filesystem scan reads it.", row.id, prefix),
			"It disables caching for the request and, in the same snippet, tests the "+
				"visitor against a search or SEO crawler. Cloaks need both: the decision "+
				"is per request, so the page must not be served from cache. Cache helpers "+
				"and user-agent checks are ordinary separately, but not together here.",
			"Cache defeat: "+strings.Join(cacheDefeat, ", "),
			"Crawlers named: "+strings.Join(crawler, ", ")),
		DedupKey: dbContentDedupKey(creds, prefix,
			fmt.Sprintf("Snippet %s is stored in %sposts, so no filesystem scan reads it.", row.id, prefix),
			"It disables caching for the request and, in the same snippet, tests the "+
				"visitor against a search or SEO crawler. Cloaks need both: the decision "+
				"is per request, so the page must not be served from cache. Cache helpers "+
				"and user-agent checks are ordinary separately, but not together here.",
			"Cache defeat: "+strings.Join(cacheDefeat, ", "),
			"Crawlers named: "+strings.Join(crawler, ", ")),
	}
}

// storedCloakNote adds the cloak components to a snippet that already matched a
// signature, rather than raising a second finding about the same row.
func storedCloakNote(cacheDefeat, crawler []string) string {
	if len(cacheDefeat) == 0 || len(crawler) == 0 {
		return ""
	}
	return fmt.Sprintf("\nIt also cloaks: caching is disabled for the request (%s) "+
		"while the visitor is tested against %s, so what a crawler is served is "+
		"not what a visitor sees.",
		strings.Join(cacheDefeat, ", "), strings.Join(crawler, ", "))
}
