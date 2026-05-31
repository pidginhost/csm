package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// nestedEvalDecodeRe matches the PHP token sequence
// `<eval|assert> [ws] ( [ws] [@] [\] <ident> [ws] (`, with DOTALL so the
// source can have line breaks inside the whitespace gaps. Attackers wedge
// comments or common call modifiers between the sink and decoder; comments and
// strings are stripped before matching so only executable token structure is
// evaluated.
var nestedEvalDecodeRe = regexp.MustCompile(`(?is)\b(eval|assert)\s*\(\s*@?\s*\\?\s*(\w+)\s*\(`)

// reEvalVarCallee matches eval wrapping a variable function call,
// e.g. `eval($f(...))`. The literal-callee form above cannot capture a
// `$var` callee, yet eval'ing the result of a dynamic function call is a
// near-certain dropper signal in user web directories.
var reEvalVarCallee = regexp.MustCompile(`(?is)\beval\s*\(\s*@?\s*\$\w+\s*\(`)

// evalExecWrapInner lists code-construction primitives that, when wrapped
// directly by eval, indicate dynamic code execution rather than the
// decoder/decompressor chain nestedEvalDecodeRe already covers.
var evalExecWrapInner = map[string]struct{}{
	"create_function":      {},
	"call_user_func":       {},
	"call_user_func_array": {},
}

var callbackFirstArgFuncs = map[string]struct{}{
	"array_map":                  {},
	"call_user_func":             {},
	"call_user_func_array":       {},
	"register_shutdown_function": {},
	"register_tick_function":     {},
}

// callbackExecNames are names that execute code when used as a callback. They
// are RCE regardless of where the call's arguments come from, so they flag
// unconditionally.
var callbackExecNames = map[string]struct{}{
	"assert":          {},
	"call_user_func":  {},
	"create_function": {},
	"eval":            {},
	"exec":            {},
	"passthru":        {},
	"popen":           {},
	"proc_open":       {},
	"shell_exec":      {},
	"system":          {},
}

// callbackDecoderNames are decode/decompress primitives. As a callback they
// only transform data (array_map('base64_decode', $data) returns decoded
// bytes, it executes nothing), so legitimate plugins use them constantly. They
// only signal a dropper when the same call is fed request input; the
// decode-then-eval shape is covered separately by the eval-chain detectors.
var callbackDecoderNames = map[string]struct{}{
	"base64_decode": {},
	"gzinflate":     {},
	"gzuncompress":  {},
	"str_rot13":     {},
}

// reVarVarCall matches a variable-variable or dynamic-expression function
// invocation, e.g. `$$h(...)` or `${$x}(...)`. On its own this shows up in
// some dispatcher code, so it is only treated as an indicator when the same
// line also carries a request superglobal (the RCE shape).
var reVarVarCall = regexp.MustCompile(`(?:\$\$\w+|\$\{[^}]{1,64}\})\s*\(`)

// includeDangerWrappers are stream wrappers / remote schemes that, as an
// include/require target, mean remote-file inclusion or php://input code
// execution. Matched on the comment-stripped (strings preserved) source.
var includeDangerWrappers = []string{"data://", "php://", "phar://", "http://", "https://", "ftp://"}

var includeKeywords = []string{"include_once", "require_once", "include", "require"}

var (
	pregReplaceCallName        = map[string]struct{}{"preg_replace": {}}
	codeEvalPrimitiveCallNames = map[string]struct{}{"assert": {}, "create_function": {}}
	callUserFuncCallNames      = map[string]struct{}{"call_user_func": {}, "call_user_func_array": {}}
)

const phpContentReadSize = 32768 // Read first 32KB for analysis

func hasBacktickSuperglobal(code string) bool {
	for i := 0; i < len(code); i++ {
		if isPHPQuote(code[i]) {
			i = skipPHPString(code, i)
			continue
		}
		if code[i] != '`' {
			continue
		}

		end := i + 1
		for end < len(code) {
			if code[end] == '\\' && end+1 < len(code) {
				end += 2
				continue
			}
			if code[end] == '`' {
				break
			}
			end++
		}
		if end >= len(code) {
			break
		}
		if containsRequestSuperglobal(code[i+1 : end]) {
			return true
		}
		i = end
	}
	return false
}

func hasCallbackExecName(code string) bool {
	for i := 0; i < len(code); i++ {
		if isPHPQuote(code[i]) {
			i = skipPHPString(code, i)
			continue
		}

		nameStart := i
		if code[i] == '\\' {
			if i+1 >= len(code) || !isPHPIdentifierStart(code[i+1]) || !canStartGlobalPHPFunction(code, i) {
				continue
			}
			nameStart = i + 1
		} else if !isPHPIdentifierStart(code[i]) || !canStartPHPFunctionName(code, i) {
			continue
		}

		nameEnd := nameStart + 1
		for nameEnd < len(code) && isPHPIdentifierPart(code[nameEnd]) {
			nameEnd++
		}
		name := strings.ToLower(code[nameStart:nameEnd])
		if _, ok := callbackFirstArgFuncs[name]; !ok {
			i = nameEnd - 1
			continue
		}

		openParen := skipPHPWhitespace(code, nameEnd)
		if openParen >= len(code) || code[openParen] != '(' {
			i = nameEnd - 1
			continue
		}
		firstArg := skipPHPWhitespace(code, openParen+1)
		if firstArg >= len(code) || !isPHPQuote(code[firstArg]) {
			i = nameEnd - 1
			continue
		}
		callbackName, _, ok := readPHPFunctionString(code, firstArg)
		if !ok {
			i = nameEnd - 1
			continue
		}
		if _, dangerous := callbackExecNames[callbackName]; dangerous {
			return true
		}
		if _, decoder := callbackDecoderNames[callbackName]; decoder {
			closeParen := matchingParen(code, openParen)
			if containsRequestSuperglobalExpression(code[openParen:closeParen]) {
				return true
			}
		}
		i = nameEnd - 1
	}
	return false
}

// matchingParen returns the index of the close paren matching the open paren
// at openParen, or len(code) if unbalanced. Quoted strings are skipped so
// parens inside string literals do not throw off the depth count.
func matchingParen(code string, openParen int) int {
	depth := 0
	for i := openParen; i < len(code); i++ {
		if isPHPQuote(code[i]) {
			i = skipPHPString(code, i)
			continue
		}
		switch code[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(code)
}

// hasDangerousInclude reports an include/require whose target is request
// input or a remote/stream wrapper -- the LFI/RFI and php://input code-exec
// shapes. Scans the include expression, not the whole line, so unrelated
// request reads or URLs after a static include do not trip the detector.
func hasDangerousInclude(code string) bool {
	searchFrom := 0
	for {
		exprStart, exprEnd, ok := nextIncludeExpression(code, searchFrom)
		if !ok {
			break
		}
		expr := code[exprStart:exprEnd]
		if containsIncludeTargetExpression(expr) {
			return true
		}
		exprLower := strings.ToLower(expr)
		for _, w := range includeDangerWrappers {
			if strings.Contains(exprLower, w) {
				return true
			}
		}
		searchFrom = exprEnd
		if searchFrom >= len(code) {
			break
		}
	}
	return false
}

// hasCodeEvalPrimitiveWithRequest reports assert()/create_function() fed
// request input on the same line. assert() evaluates a string argument as PHP
// (pre-8.0) and create_function() evals its body argument; both are RCE when
// driven by attacker input.
func hasCodeEvalPrimitiveWithRequest(code string) bool {
	for _, line := range strings.Split(code, "\n") {
		searchFrom := 0
		for {
			_, openParen, closeParen, ok := nextStandalonePHPCall(line, searchFrom, codeEvalPrimitiveCallNames)
			if !ok {
				break
			}
			exprEnd := closeParen
			if exprEnd < len(line) {
				exprEnd++
			}
			if containsRequestSuperglobal(line[openParen:exprEnd]) {
				return true
			}
			searchFrom = exprEnd
			if searchFrom >= len(line) {
				break
			}
		}
	}
	return false
}

// hasPregReplaceEvalWithRequest reports a preg_replace() call whose pattern
// carries the /e modifier and whose evaluated replacement or subject reads
// request input. The /e modifier (removed in PHP 7.0) evaluates the replacement
// as PHP after backreferences from the subject are interpolated, so pattern-only
// request input is not enough to call this a code-execution sink. Bare /e with
// static arguments is the legacy WordPress serialize-fix / autolink idiom --
// real /e usage, but not a dropper -- so it is gated on request-input
// correlation, the same way the shell, include, and assert detectors here gate
// their sinks.
// Walks the source skipping string literals so a documentation example in a
// string does not trip, then inspects the literal first argument of each call.
func hasPregReplaceEvalWithRequest(code string) bool {
	searchFrom := 0
	for {
		callStart, openParen, closeParen, ok := nextStandalonePHPCall(code, searchFrom, pregReplaceCallName)
		if !ok {
			break
		}
		args := phpCallArguments(code, openParen+1, closeParen)
		if len(args) < 3 || !pregPatternArgumentHasEvalModifier(args[0]) {
			searchFrom = nextSearchOffset(closeParen, len(code))
			continue
		}
		tainted := requestTaintedVariablesBefore(code, callStart)
		if pregReplacementReadsRequest(args[1], tainted) || phpExpressionReadsRequest(args[2], tainted) {
			return true
		}
		searchFrom = nextSearchOffset(closeParen, len(code))
	}
	return false
}

func pregPatternArgumentHasEvalModifier(expr string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" || !isPHPQuote(expr[0]) {
		return false
	}
	end := skipPHPString(expr, 0)
	// skipPHPString returns the closing-quote index, or the last index for an
	// unterminated literal. Guard the slice: a quote in the final position
	// leaves no string body to inspect.
	if end <= 0 {
		return false
	}
	return pregPatternHasEvalModifier(expr[1:end])
}

func pregReplacementReadsRequest(expr string, tainted map[string]struct{}) bool {
	if phpExpressionReadsRequest(expr, tainted) {
		return true
	}
	body, _, ok := phpStringLiteralExpression(expr)
	if !ok {
		return false
	}
	return phpExpressionReadsRequest(body, tainted)
}

func phpExpressionReadsRequest(expr string, tainted map[string]struct{}) bool {
	return containsRequestSuperglobalExpression(expr) || phpExpressionReferencesTaintedVariable(expr, tainted)
}

func phpExpressionReferencesTaintedVariable(expr string, tainted map[string]struct{}) bool {
	if len(tainted) == 0 {
		return false
	}
	for i := 0; i < len(expr); i++ {
		if isPHPQuote(expr[i]) {
			i = skipPHPString(expr, i)
			continue
		}
		if expr[i] != '$' {
			continue
		}
		variable, next, ok := readPHPVariableName(expr, i)
		if !ok {
			continue
		}
		if _, found := tainted[variable]; found {
			return true
		}
		i = next - 1
	}
	return false
}

func requestTaintedVariablesBefore(code string, limit int) map[string]struct{} {
	if limit > len(code) {
		limit = len(code)
	}
	if limit <= 0 {
		return nil
	}
	scan := code[:limit]
	taintStack := []map[string]struct{}{{}}
	functionBraceStack := []bool{}
	pendingFunctionScope := false
	for i := 0; i < len(scan); i++ {
		if isPHPQuote(scan[i]) {
			i = skipPHPString(scan, i)
			continue
		}
		if end, ok := phpKeywordAt(scan, i, "function"); ok {
			pendingFunctionScope = true
			i = end - 1
			continue
		}
		switch scan[i] {
		case '{':
			functionBraceStack = append(functionBraceStack, pendingFunctionScope)
			if pendingFunctionScope {
				taintStack = append(taintStack, map[string]struct{}{})
			}
			pendingFunctionScope = false
			continue
		case '}':
			if len(functionBraceStack) > 0 {
				last := len(functionBraceStack) - 1
				if functionBraceStack[last] && len(taintStack) > 1 {
					taintStack = taintStack[:len(taintStack)-1]
				}
				functionBraceStack = functionBraceStack[:last]
			}
			pendingFunctionScope = false
			continue
		case ';':
			pendingFunctionScope = false
		}
		if scan[i] != '$' {
			continue
		}
		variable, next, ok := readPHPVariableName(scan, i)
		if !ok || isRequestSuperglobalVariable(variable) {
			continue
		}
		j := skipPHPWhitespace(scan, next)
		opLen, directAssign, appendAssign, ok := phpAssignmentOperator(scan, j)
		if !ok {
			i = next - 1
			continue
		}
		exprStart := skipPHPWhitespace(scan, j+opLen)
		exprEnd := phpExpressionEnd(scan, exprStart)
		expr := scan[exprStart:exprEnd]
		tainted := taintStack[len(taintStack)-1]
		exprTainted := phpExpressionReadsRequest(expr, tainted)
		switch {
		case directAssign:
			if exprTainted {
				tainted[variable] = struct{}{}
			} else {
				delete(tainted, variable)
			}
		case appendAssign:
			if exprTainted {
				tainted[variable] = struct{}{}
			}
		default:
			if exprTainted {
				tainted[variable] = struct{}{}
			} else {
				delete(tainted, variable)
			}
		}
		i = exprEnd - 1
	}
	return taintStack[len(taintStack)-1]
}

func phpKeywordAt(code string, start int, keyword string) (int, bool) {
	end := start + len(keyword)
	if end > len(code) || !strings.EqualFold(code[start:end], keyword) {
		return 0, false
	}
	if start > 0 {
		prev := code[start-1]
		if isPHPIdentifierPart(prev) || prev == '$' || prev == '>' || prev == ':' || prev == '\\' {
			return 0, false
		}
	}
	if end < len(code) && isPHPIdentifierPart(code[end]) {
		return 0, false
	}
	return end, true
}

func isRequestSuperglobalVariable(variable string) bool {
	switch strings.ToLower(variable) {
	case "_request", "_post", "_get", "_cookie", "_server":
		return true
	default:
		return false
	}
}

func phpStringLiteralExpression(expr string) (string, byte, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || !isPHPQuote(expr[0]) {
		return "", 0, false
	}
	end := skipPHPString(expr, 0)
	if end <= 0 || end >= len(expr) || expr[end] != expr[0] {
		return "", 0, false
	}
	if skipPHPWhitespace(expr, end+1) != len(expr) {
		return "", 0, false
	}
	return expr[1:end], expr[0], true
}

func phpCallArguments(code string, start, end int) []string {
	if start < 0 {
		start = 0
	}
	if end > len(code) {
		end = len(code)
	}
	if start > end {
		return nil
	}

	var args []string
	argStart := skipPHPWhitespace(code, start)
	depth := 0
	for i := start; i < end; i++ {
		if isPHPQuote(code[i]) {
			i = skipPHPString(code, i)
			continue
		}
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(code[argStart:i]))
				argStart = skipPHPWhitespace(code, i+1)
			}
		}
	}
	if tail := strings.TrimSpace(code[argStart:end]); tail != "" || len(args) > 0 {
		args = append(args, tail)
	}
	return args
}

// pregPatternHasEvalModifier returns true when the PCRE pattern string carries
// an "e" modifier after its closing delimiter.
func pregPatternHasEvalModifier(pat string) bool {
	if len(pat) < 2 {
		return false
	}
	open := pat[0]
	// PHP forbids alphanumeric, backslash, and whitespace delimiters.
	if isPHPIdentifierPart(open) || open == '\\' || open == ' ' {
		return false
	}
	closeDelim := open
	switch open {
	case '(':
		closeDelim = ')'
	case '[':
		closeDelim = ']'
	case '{':
		closeDelim = '}'
	case '<':
		closeDelim = '>'
	}
	idx := strings.LastIndexByte(pat, closeDelim)
	if idx <= 0 {
		return false
	}
	for _, c := range pat[idx+1:] {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
		if c == 'e' {
			return true
		}
	}
	return false
}

func nextIncludeExpression(line string, searchFrom int) (int, int, bool) {
	for i := searchFrom; i < len(line); i++ {
		if isPHPQuote(line[i]) {
			i = skipPHPString(line, i)
			continue
		}
		keywordEnd, ok := includeKeywordEnd(line, i)
		if !ok {
			continue
		}
		exprStart := skipPHPWhitespace(line, keywordEnd)
		return exprStart, phpExpressionEnd(line, exprStart), true
	}
	return 0, 0, false
}

func includeKeywordEnd(line string, start int) (int, bool) {
	if !canStartIncludeKeyword(line, start) {
		return 0, false
	}
	for _, keyword := range includeKeywords {
		end := start + len(keyword)
		if end > len(line) || !strings.EqualFold(line[start:end], keyword) {
			continue
		}
		if end < len(line) && isPHPIdentifierPart(line[end]) {
			continue
		}
		return end, true
	}
	return 0, false
}

func canStartIncludeKeyword(line string, start int) bool {
	if start == 0 {
		return true
	}
	prev := line[start-1]
	return !isPHPIdentifierPart(prev) && prev != '$' && prev != '>' && prev != ':' && prev != '\\'
}

func phpExpressionEnd(code string, start int) int {
	depth := 0
	for i := start; i < len(code); i++ {
		if isPHPQuote(code[i]) {
			i = skipPHPString(code, i)
			continue
		}
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return i
			}
			depth--
		case ';':
			if depth == 0 {
				return i
			}
		case ',':
			if depth == 0 {
				return i
			}
		}
	}
	return len(code)
}

// phpCodeOnly blanks the inline-HTML regions of a PHP source so only the code
// inside <?php ... ?> (and <?= ... ?>) spans is analysed for execution sinks.
// Inline HTML is literal output and cannot execute PHP, so scanning it as code
// only yields false positives: apostrophes in prose ("don't", "you're") desync
// the string scanner, and href URLs, JS backtick template literals, and English
// words like "include"/"require" in markup then read as PHP execution sinks.
//
// HTML bytes become spaces (newlines kept so line-oriented detectors keep their
// line structure); a closing "?>" becomes "; " so it still bounds the preceding
// statement and consecutive <?php?> blocks do not run their expressions
// together. The "?>" scan skips PHP strings, heredoc/nowdoc bodies, and block
// comments so a "?>" inside them does not end PHP mode and blank real code. A
// file with no PHP open tag yields all blanks -- it executes nothing.
func phpCodeOnly(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	n := len(src)
	i := 0
	for i < n {
		// HTML mode: blank up to the next "<?" open tag.
		htmlStart := i
		for i < n && (src[i] != '<' || i+1 >= n || src[i+1] != '?') {
			i++
		}
		blankInlineHTML(&b, src[htmlStart:i])
		if i >= n {
			break
		}
		// Blank the opening tag: "<?php" (needs trailing whitespace/EOF), "<?=",
		// or a bare "<?" short tag.
		i += 2
		b.WriteString("  ")
		if i+3 <= n && strings.EqualFold(src[i:i+3], "php") && (i+3 == n || isPHPSpace(src[i+3])) {
			b.WriteString("   ")
			i += 3
		} else if i < n && src[i] == '=' {
			b.WriteByte(' ')
			i++
		}
		// PHP mode: copy verbatim until a top-level "?>".
		i = copyPHPModeRegion(&b, src, i)
	}
	return b.String()
}

// copyPHPModeRegion copies src[start:] into b verbatim until a top-level "?>"
// (which it replaces with "; ") or EOF, and returns the resume index. Strings,
// heredoc/nowdoc bodies, and block comments are copied whole so a "?>" inside
// them is not mistaken for a closing tag. A "?>" inside a // or # line comment
// does end PHP mode, matching PHP's own tokeniser.
func copyPHPModeRegion(b *strings.Builder, src string, start int) int {
	n := len(src)
	i := start
	for i < n {
		if label, bodyStart, ok := phpHeredocOpen(src, i); ok {
			end := phpHeredocEnd(src, bodyStart, label)
			b.WriteString(src[i:end])
			i = end
			continue
		}
		if isPHPQuote(src[i]) {
			i = copyPHPString(b, src, i) + 1
			continue
		}
		if src[i] == '/' && i+1 < n && src[i+1] == '*' {
			b.WriteString("/*")
			i += 2
			for i < n {
				if src[i] == '*' && i+1 < n && src[i+1] == '/' {
					b.WriteString("*/")
					i += 2
					break
				}
				b.WriteByte(src[i])
				i++
			}
			continue
		}
		if (src[i] == '/' && i+1 < n && src[i+1] == '/') || src[i] == '#' {
			for i < n && src[i] != '\n' {
				if src[i] == '?' && i+1 < n && src[i+1] == '>' {
					break
				}
				b.WriteByte(src[i])
				i++
			}
			if i+1 < n && src[i] == '?' && src[i+1] == '>' {
				b.WriteString("; ")
				return i + 2
			}
			continue
		}
		if src[i] == '?' && i+1 < n && src[i+1] == '>' {
			b.WriteString("; ")
			return i + 2
		}
		b.WriteByte(src[i])
		i++
	}
	return i
}

// blankInlineHTML writes s as spaces, preserving newlines so line-based
// detectors keep their line boundaries across blanked template text.
func blankInlineHTML(b *strings.Builder, s string) {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			b.WriteByte(s[i])
		} else {
			b.WriteByte(' ')
		}
	}
}

func nextStandalonePHPCall(code string, searchFrom int, names map[string]struct{}) (int, int, int, bool) {
	for i := searchFrom; i < len(code); i++ {
		if isPHPQuote(code[i]) {
			i = skipPHPString(code, i)
			continue
		}

		nameStart := i
		if code[i] == '\\' {
			if i+1 >= len(code) || !isPHPIdentifierStart(code[i+1]) || !canStartGlobalPHPFunction(code, i) {
				continue
			}
			nameStart = i + 1
		} else if !isPHPIdentifierStart(code[i]) || !canStartPHPFunctionName(code, i) {
			continue
		}

		nameEnd := nameStart + 1
		for nameEnd < len(code) && isPHPIdentifierPart(code[nameEnd]) {
			nameEnd++
		}
		if _, ok := names[strings.ToLower(code[nameStart:nameEnd])]; !ok {
			i = nameEnd - 1
			continue
		}

		openParen := skipPHPWhitespace(code, nameEnd)
		if openParen >= len(code) || code[openParen] != '(' {
			i = nameEnd - 1
			continue
		}
		return i, openParen, matchingParen(code, openParen), true
	}
	return 0, 0, 0, false
}

func nextSearchOffset(pos, codeLen int) int {
	if pos >= codeLen {
		return codeLen
	}
	return pos + 1
}

var requestSuperglobalNames = []string{"$_request", "$_post", "$_get", "$_cookie", "$_server"}

// includeTargetSuperglobalNames omits $_SERVER path keys: including a path
// built from the server document root or script filename is the standard
// WordPress bootstrap idiom, not an LFI/RFI primitive. Header-derived
// $_SERVER keys are handled separately below.
var includeTargetSuperglobalNames = []string{"$_request", "$_post", "$_get", "$_cookie"}

func containsRequestSuperglobal(code string) bool {
	return containsAnySuperglobal(code, requestSuperglobalNames)
}

func containsAnySuperglobal(code string, names []string) bool {
	code = strings.ToLower(code)
	for _, requestVar := range names {
		searchFrom := 0
		for {
			pos := strings.Index(code[searchFrom:], requestVar)
			if pos < 0 {
				break
			}
			end := searchFrom + pos + len(requestVar)
			if end >= len(code) || !isPHPIdentifierPart(code[end]) {
				return true
			}
			searchFrom = end
		}
	}
	return false
}

// PHP single-quoted strings do not interpolate variables, but double-quoted
// strings do. The decoder callback gate needs that distinction so a literal
// '$_POST' data value does not look like request input.
func containsRequestSuperglobalExpression(code string) bool {
	return containsSuperglobalExpression(code, requestSuperglobalNames)
}

// containsIncludeTargetExpression reports whether an include/require target
// expression reads an attacker-controlled superglobal. Non-header $_SERVER
// path keys are left alone (see includeTargetSuperglobalNames).
func containsIncludeTargetExpression(code string) bool {
	return containsSuperglobalExpression(code, includeTargetSuperglobalNames) ||
		containsServerHeaderIncludeExpression(code)
}

func containsSuperglobalExpression(code string, names []string) bool {
	start := 0
	for i := 0; i < len(code); i++ {
		if !isPHPQuote(code[i]) {
			continue
		}
		if containsAnySuperglobal(code[start:i], names) {
			return true
		}
		end := skipPHPString(code, i)
		if code[i] == '"' && containsAnySuperglobal(code[i:end+1], names) {
			return true
		}
		i = end
		start = end + 1
	}
	return containsAnySuperglobal(code[start:], names)
}

func containsServerHeaderIncludeExpression(code string) bool {
	for i := 0; i < len(code); i++ {
		if isPHPQuote(code[i]) {
			end := skipPHPString(code, i)
			if code[i] == '"' && end > i && containsServerHeaderReference(code[i+1:end]) {
				return true
			}
			i = end
			continue
		}
		dangerous, next, ok := serverIncludeReferenceAt(code, i)
		if !ok {
			continue
		}
		if dangerous {
			return true
		}
		i = next - 1
	}
	return false
}

func containsServerHeaderReference(code string) bool {
	for i := 0; i < len(code); i++ {
		dangerous, next, ok := serverIncludeReferenceAt(code, i)
		if !ok {
			continue
		}
		if dangerous {
			return true
		}
		i = next - 1
	}
	return false
}

func serverIncludeReferenceAt(code string, start int) (bool, int, bool) {
	const serverName = "$_server"
	end := start + len(serverName)
	if end > len(code) || !strings.EqualFold(code[start:end], serverName) {
		return false, start, false
	}
	if end < len(code) && isPHPIdentifierPart(code[end]) {
		return false, start, false
	}

	bracket := skipPHPWhitespace(code, end)
	if bracket >= len(code) || code[bracket] != '[' {
		return true, end, true
	}
	keyStart := skipPHPWhitespace(code, bracket+1)
	if keyStart >= len(code) {
		return true, len(code), true
	}
	if isPHPQuote(code[keyStart]) {
		keyEnd := skipPHPString(code, keyStart)
		key := phpStringLiteralValue(code, keyStart, keyEnd)
		next := skipPHPWhitespace(code, keyEnd+1)
		if next < len(code) && code[next] == ']' {
			return isAttackerControlledServerKey(key), next + 1, true
		}
		return true, next, true
	}
	if isPHPIdentifierStart(code[keyStart]) {
		keyEnd := keyStart + 1
		for keyEnd < len(code) && isPHPIdentifierPart(code[keyEnd]) {
			keyEnd++
		}
		key := code[keyStart:keyEnd]
		next := skipPHPWhitespace(code, keyEnd)
		if next < len(code) && code[next] == ']' {
			return isAttackerControlledServerKey(key), next + 1, true
		}
		return true, next, true
	}
	return true, keyStart + 1, true
}

func phpStringLiteralValue(code string, start, end int) string {
	var b strings.Builder
	quote := code[start]
	for i := start + 1; i < end; i++ {
		if code[i] != '\\' || i+1 >= end {
			b.WriteByte(code[i])
			continue
		}
		i++
		esc := code[i]
		if quote == '\'' {
			if esc == '\'' || esc == '\\' {
				b.WriteByte(esc)
			} else {
				b.WriteByte('\\')
				b.WriteByte(esc)
			}
			continue
		}
		switch esc {
		case 'x':
			if i+1 >= end || !isHexDigit(code[i+1]) {
				b.WriteByte('\\')
				b.WriteByte(esc)
				continue
			}
			value := hexVal(code[i+1])
			i++
			if i+1 < end && isHexDigit(code[i+1]) {
				value = value*16 + hexVal(code[i+1])
				i++
			}
			// #nosec G115 -- PHP hex string escapes are at most one byte.
			b.WriteByte(byte(value))
		case 'u':
			if i+2 >= end || code[i+1] != '{' || !isHexDigit(code[i+2]) {
				b.WriteByte('\\')
				b.WriteByte(esc)
				continue
			}
			value := 0
			j := i + 2
			for ; j < end && isHexDigit(code[j]); j++ {
				value = value*16 + hexVal(code[j])
			}
			if j >= end || code[j] != '}' {
				b.WriteByte('\\')
				b.WriteByte(esc)
				continue
			}
			if value > 0x10ffff {
				b.WriteByte('\\')
				b.WriteByte(esc)
				continue
			}
			// #nosec G115 -- value is capped at the largest valid Unicode code point.
			b.WriteRune(rune(value))
			i = j
		case '0', '1', '2', '3', '4', '5', '6', '7':
			value := int(esc - '0')
			digits := 1
			for i+1 < end && digits < 3 && code[i+1] >= '0' && code[i+1] <= '7' {
				value = value*8 + int(code[i+1]-'0')
				i++
				digits++
			}
			// #nosec G115 -- PHP octal string escapes are byte escapes.
			b.WriteByte(byte(value))
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte('\v')
		case 'e':
			b.WriteByte(0x1b)
		case 'f':
			b.WriteByte('\f')
		case '\\', '$', '"':
			b.WriteByte(esc)
		default:
			b.WriteByte('\\')
			b.WriteByte(esc)
		}
	}
	return b.String()
}

func isAttackerControlledServerKey(key string) bool {
	key = strings.ToUpper(strings.TrimSpace(key))
	if strings.HasPrefix(key, "HTTP_") {
		return true
	}
	switch key {
	case "CONTENT_LENGTH", "CONTENT_TYPE", "PHP_AUTH_DIGEST", "PHP_AUTH_PW", "PHP_AUTH_USER":
		return true
	default:
		return false
	}
}

func canStartGlobalPHPFunction(code string, slash int) bool {
	if slash == 0 {
		return true
	}
	prev := code[slash-1]
	return !isPHPIdentifierPart(prev) && prev != '$' && prev != '>' && prev != ':' && prev != '\\'
}

func canStartPHPFunctionName(code string, start int) bool {
	if start == 0 {
		return true
	}
	prev := code[start-1]
	return !isPHPIdentifierPart(prev) && prev != '$' && prev != '>' && prev != ':' && prev != '\\'
}

// CheckPHPContent scans new/suspicious PHP files for obfuscation patterns,
// remote payload fetching, and eval chains. This is designed to catch droppers
// like the LEVIATHAN attack's file.php and files.php that use goto spaghetti,
// hex-encoded strings, and call_user_func with string-built function names.
//
// This check scans PHP files in directories that shouldn't normally contain
// user-authored PHP: wp-content/languages, wp-content/upgrade, wp-content/mu-plugins,
// and also checks any PHP files flagged by the file index as new.
// phpFileStamp is the cheap content-version key for a scanned PHP file. A file
// whose mtime and size both match the previous cycle is treated as unchanged.
type phpFileStamp struct {
	Mtime int64 `json:"m"`
	Size  int64 `json:"s"`
}

// phpContentCache maps a file path to the stamp it carried when last confirmed
// clean. Only clean files are stored, so a present, matching entry means
// "unchanged and previously produced no finding."
type phpContentCache map[string]phpFileStamp

func loadPHPContentCache(stateDir string) phpContentCache {
	cache := phpContentCache{}
	if stateDir == "" {
		return cache
	}
	data, err := osFS.ReadFile(filepath.Join(stateDir, "phpcontentcache.json"))
	if err == nil {
		_ = json.Unmarshal(data, &cache)
	}
	return cache
}

func savePHPContentCache(stateDir string, cache phpContentCache) {
	if stateDir == "" {
		return
	}
	data, _ := json.Marshal(cache)
	tmpPath := filepath.Join(stateDir, "phpcontentcache.json.tmp")
	_ = os.WriteFile(tmpPath, data, 0600)
	_ = os.Rename(tmpPath, filepath.Join(stateDir, "phpcontentcache.json"))
}

// phpContentHostScanCount drives a periodic forced full rescan that bypasses
// the content cache, mirroring the file-index cadence. The cache keys on
// mtime+size alone, so a content swap that preserves both (an attacker resetting
// mtime after editing in place) would be skipped until the file changed again.
// The forced rescan bounds that window; realtime fanotify covers it in between.
var phpContentHostScanCount int32

// phpContentAccountScanCount keeps account-scoped scans from consuming the
// host-wide full-rescan cadence. Account scans are subsets and never save the
// shared cache, so mixing the counters can make the host-wide backstop miss its
// intended cycle.
var phpContentAccountScanCount int32

func phpContentForceFull(ctx context.Context) bool {
	if AccountFromContext(ctx) != "" {
		return atomic.AddInt32(&phpContentAccountScanCount, 1)%6 == 0
	}
	return atomic.AddInt32(&phpContentHostScanCount, 1)%6 == 0
}

// phpContentScan carries the per-cycle cache state through the recursive walk.
// prev is the previous cycle's clean-file stamps (read-only); next is rebuilt
// from the files seen this cycle, which prunes deleted files automatically.
type phpContentScan struct {
	cfg       *config.Config
	prev      phpContentCache
	next      phpContentCache
	forceFull bool
}

func newPHPContentScan(cfg *config.Config, prev phpContentCache, forceFull bool) *phpContentScan {
	if prev == nil {
		prev = phpContentCache{}
	}
	return &phpContentScan{cfg: cfg, prev: prev, next: phpContentCache{}, forceFull: forceFull}
}

func CheckPHPContent(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	homeDirs, err := GetScanHomeDirs(ctx)
	if err != nil {
		return nil
	}

	scan := newPHPContentScan(cfg, loadPHPContentCache(cfg.StatePath), phpContentForceFull(ctx))

	for _, homeEntry := range homeDirs {
		if ctx.Err() != nil {
			return findings
		}
		if !homeEntry.IsDir() {
			continue
		}
		homeDir := filepath.Join("/home", homeEntry.Name())

		// Get all potential document roots
		docRoots := []string{filepath.Join(homeDir, "public_html")}
		subDirs, _ := osFS.ReadDir(homeDir)
		for _, sd := range subDirs {
			if sd.IsDir() && sd.Name() != "public_html" && sd.Name() != "mail" &&
				!strings.HasPrefix(sd.Name(), ".") && sd.Name() != "etc" &&
				sd.Name() != "logs" && sd.Name() != "ssl" && sd.Name() != "tmp" {
				docRoots = append(docRoots, filepath.Join(homeDir, sd.Name()))
			}
		}

		for _, docRoot := range docRoots {
			// Scan directories that shouldn't contain user PHP
			suspiciousDirs := []string{
				filepath.Join(docRoot, "wp-content", "languages"),
				filepath.Join(docRoot, "wp-content", "upgrade"),
				filepath.Join(docRoot, "wp-content", "mu-plugins"),
				filepath.Join(docRoot, "wp-content", "plugins"),
				filepath.Join(docRoot, "wp-content", "themes"),
			}

			for _, dir := range suspiciousDirs {
				scan.scanDir(ctx, dir, 4, &findings)
				if ctx.Err() != nil {
					return findings
				}
			}
		}
	}

	// Persist only after a complete host-wide scan. A run cut short by ctx
	// timeout leaves scan.next missing the unscanned files; persisting it would
	// drop their cached-clean state and force a needless re-read next cycle
	// (still safe, just slower). An account-scoped run (account_scan) only walks
	// one account, so its scan.next is a subset of the shared cache and must not
	// overwrite the host-wide stamps.
	if ctx.Err() == nil && AccountFromContext(ctx) == "" {
		savePHPContentCache(cfg.StatePath, scan.next)
	}

	return findings
}

// scanDirForObfuscatedPHP scans dir without the content cache: every PHP file
// is read and analysed. Used where caching does not apply (no prior cycle to
// compare against).
func scanDirForObfuscatedPHP(ctx context.Context, dir string, maxDepth int, cfg *config.Config, findings *[]alert.Finding) {
	newPHPContentScan(cfg, nil, true).scanDir(ctx, dir, maxDepth, findings)
}

// scanDir recursively scans dir for PHP files with malicious content patterns.
// A file that was clean last cycle and is unchanged (same mtime+size) skips the
// read+parse, unless this is a forced full rescan. Files that produce a finding
// are never cached, so they re-surface on every cycle for the alert pipeline.
func (s *phpContentScan) scanDir(ctx context.Context, dir string, maxDepth int, findings *[]alert.Finding) {
	if ctx.Err() != nil {
		return
	}
	if maxDepth <= 0 {
		return
	}
	entries, err := osFS.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		name := entry.Name()
		fullPath := filepath.Join(dir, name)

		// Check suppressed paths
		suppressed := false
		for _, ignore := range s.cfg.Suppressions.IgnorePaths {
			if matchGlob(fullPath, ignore) {
				suppressed = true
				break
			}
		}
		if suppressed {
			continue
		}

		if entry.IsDir() {
			s.scanDir(ctx, fullPath, maxDepth-1, findings)
			continue
		}

		nameLower := strings.ToLower(name)
		if !strings.HasSuffix(nameLower, ".php") {
			continue
		}

		info, statErr := osFS.Stat(fullPath)
		var stamp phpFileStamp
		canCache := statErr == nil
		if canCache {
			stamp = phpFileStamp{Mtime: info.ModTime().Unix(), Size: info.Size()}
			// Cache hit: file was clean last cycle and has not changed. Skip
			// the read+parse and carry the stamp forward only if the file is
			// still readable. chmod does not update mtime or size, so a stale
			// clean cache entry must not mask a file we can no longer inspect.
			if !s.forceFull {
				if prev, ok := s.prev[fullPath]; ok && prev == stamp {
					if phpContentReadable(fullPath) {
						s.next[fullPath] = stamp
						continue
					}
				}
			}
		}

		// Every .php file is content-analysed. No filename/path allowlist:
		// clean files produce no finding, so there is no benefit to skipping
		// them, and any skip is a place an attacker can hide a backdoor.
		result := analyzePHPContent(fullPath)
		if result.severity >= 0 {
			details := result.details
			if info != nil {
				details += fmt.Sprintf("\nSize: %d, Mtime: %s", info.Size(), info.ModTime().Format("2006-01-02 15:04:05"))
			}
			*findings = append(*findings, alert.Finding{
				Severity: result.severity,
				Check:    result.check,
				Message:  fmt.Sprintf("%s: %s", result.message, fullPath),
				Details:  details,
				FilePath: fullPath,
			})
			continue
		}

		// Cache only files we read successfully and confirmed clean. An
		// unreadable file might become readable later, so it must not be
		// recorded as clean.
		if canCache && result.readOK {
			s.next[fullPath] = stamp
		}
	}
}

func phpContentReadable(path string) bool {
	f, err := osFS.Open(path)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

type phpAnalysisResult struct {
	severity alert.Severity
	check    string
	message  string
	details  string
	readOK   bool
	empty    bool
}

// analyzePHPContent reads the first phpContentReadSize bytes of a PHP file
// and checks for obfuscation and malicious patterns.
func analyzePHPContent(path string) phpAnalysisResult {
	f, err := osFS.Open(path)
	if err != nil {
		return phpAnalysisResult{severity: -1}
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, phpContentReadSize)
	n, readErr := f.Read(buf)
	readOK := readErr == nil || errors.Is(readErr, io.EOF)
	if n == 0 {
		return phpAnalysisResult{severity: -1, readOK: readOK, empty: readOK}
	}
	content := phpCodeOnly(string(buf[:n]))
	contentLower := strings.ToLower(content)

	var indicators []string

	// --- Critical: Remote payload fetching ---
	// Paste sites are always suspicious in PHP files.
	// GitHub raw URLs are common in legitimate plugin update checkers,
	// so only count them as indicators when they appear on the same line
	// as a dangerous PHP function call.
	pasteHosts := []string{
		"pastebin.com/raw",
		"paste.ee/r/",
		"ghostbin.co/paste/",
		"hastebin.com/raw/",
	}
	for _, host := range pasteHosts {
		if strings.Contains(contentLower, host) {
			indicators = append(indicators, fmt.Sprintf("remote payload URL: %s", host))
		}
	}
	githubHosts := []string{"gist.githubusercontent.com", "raw.githubusercontent.com"}
	dangerousCalls := []string{"file_put_contents(", "fwrite(", "shell_", "passthru(", "popen("}
	for _, host := range githubHosts {
		if !strings.Contains(contentLower, host) {
			continue
		}
		// Same-line = strong signal (critical)
		sameLine := false
		for _, line := range strings.Split(contentLower, "\n") {
			if !strings.Contains(line, host) {
				continue
			}
			for _, fn := range dangerousCalls {
				if strings.Contains(line, fn) {
					indicators = append(indicators, fmt.Sprintf("remote payload URL with dangerous call: %s", host))
					sameLine = true
					break
				}
			}
			if sameLine {
				break
			}
		}
		// Co-presence (different lines, same 32 KB window) was previously
		// emitted as a weaker indicator. It generated standing FPs on
		// legit plugins that fetch upstream resources from github mirrors
		// (wp-statistics GeoLite2 updates, unyson font fetcher, polylang
		// language packs). Same-line is the strong signal kept above; the
		// co-presence path is removed entirely.
	}

	// --- Critical: eval() chains with decoding ---
	// Only flag when eval directly wraps a decoder (structural nesting),
	// not when they merely co-exist in the same file (which causes false
	// positives on legitimate plugins that use eval for templates and
	// base64_decode for unrelated data processing).
	decoders := []string{
		"base64_decode", "gzinflate", "gzuncompress", "str_rot13",
		"rawurldecode", "gzdecode", "bzdecompress",
	}
	hasDecoder := false
	hasNestedEvalDecode := false
	for _, d := range decoders {
		if strings.Contains(contentLower, d) {
			hasDecoder = true
		}
	}
	// Check for structural nesting: eval(base64_decode(...)), eval(gzinflate(...)), etc.
	// PHP tolerates inline comments and arbitrary whitespace (including line
	// breaks) between the keyword and its open paren, so a naive line-by-line
	// `eval(` substring scan misses `eval /*x*/ ( base64_decode(...))` and
	// `eval // bypass\n( base64_decode(...))`. Strip PHP comments and
	// strings first, then match the structural pattern across whitespace,
	// and require the inner callee to be one of the known decoders /
	// decompressors.
	commentStripped := stripPHPCommentsFromCode(content)
	codeLower := strings.ToLower(stripPHPStringsFromCode(commentStripped))
	for _, m := range nestedEvalDecodeRe.FindAllStringSubmatch(codeLower, -1) {
		if len(m) < 3 {
			continue
		}
		inner := m[2]
		for _, d := range decoders {
			if inner == d {
				hasNestedEvalDecode = true
				break
			}
		}
		if hasNestedEvalDecode {
			break
		}
	}
	if hasNestedEvalDecode {
		indicators = append(indicators, "eval() directly wrapping encoding/compression function")
	}

	// eval wrapping dynamic code construction the decoder loop above
	// ignores: a variable callee (eval($f(...))) or a code-building
	// primitive (eval(create_function(...)), eval(call_user_func(...))).
	// These never appear in legitimate user-directory PHP; a single hit is
	// surfaced as a High signal (the >=2 gate still governs quarantine).
	hasEvalExecWrap := reEvalVarCallee.MatchString(codeLower)
	if !hasEvalExecWrap {
		for _, m := range nestedEvalDecodeRe.FindAllStringSubmatch(codeLower, -1) {
			if len(m) < 3 {
				continue
			}
			if m[1] != "eval" {
				continue
			}
			if _, ok := evalExecWrapInner[m[2]]; ok {
				hasEvalExecWrap = true
				break
			}
		}
	}
	if hasEvalExecWrap {
		indicators = append(indicators, "eval() wrapping a dynamic code-execution primitive")
	}

	// Backtick shell execution with request input -- `...$_GET...`.
	// Match only executable backtick spans, not quoted examples.
	if hasBacktickSuperglobal(commentStripped) {
		indicators = append(indicators, "backtick shell execution with request input")
	}

	// Callback-position exec: an exec/decoder function name passed as a
	// string callback (array_map("system", ...), register_shutdown_function(
	// "passthru", ...)). Runs on the comment-stripped source so the literal
	// callback name is preserved.
	if hasCallbackExecName(commentStripped) {
		indicators = append(indicators, "exec/decoder function name passed as a callback")
	}

	// Variable-variable / dynamic-expression function call co-located with
	// request input on the same line -- $$h($_GET[...]) -- a dynamic-dispatch
	// RCE shape. The same-line request-var gate keeps benign dispatcher code
	// (which uses $$var without attacker input) from tripping.
	for _, line := range strings.Split(codeLower, "\n") {
		if reVarVarCall.MatchString(line) && lineContainsRequestVar(line) {
			indicators = append(indicators, "variable-variable function call with request input")
			break
		}
	}

	// preg_replace() with the /e modifier evaluates its replacement as PHP.
	// Removed in PHP 7.0; flag it when request input reaches the evaluated
	// replacement or its subject backreferences.
	if hasPregReplaceEvalWithRequest(commentStripped) {
		indicators = append(indicators, "preg_replace with /e modifier (code execution)")
	}

	// include/require of request input or a remote/stream wrapper -- LFI,
	// RFI, and php://input code execution.
	if hasDangerousInclude(commentStripped) {
		indicators = append(indicators, "include/require of request input or remote/data wrapper")
	}

	// assert()/create_function() driven by request input -- both evaluate a
	// string argument as PHP.
	if hasCodeEvalPrimitiveWithRequest(commentStripped) {
		indicators = append(indicators, "code-eval primitive (assert/create_function) with request input")
	}

	// --- Critical: call_user_func with string-built function names ---
	// LEVIATHAN droppers build the target function name on the call itself:
	//   call_user_func("\x63"."\x75"."\x72"."\x6c", $payload)  ==  call_user_func("curl", ...)
	// File-wide hex/concat counts are unsafe here: WPML bundles PHPZip
	// (inc/wpml_zip.php) which declares 20+ ZIP-format signature constants
	// as hex literals ("\x50\x4b\x03\x04" etc.) and makes a single benign
	// call_user_func(self::$temp) call to invoke a temp-file factory.
	// Match the obfuscation on the callable target argument itself.
	if strings.Contains(contentLower, "call_user_func") {
		foundCallUserFuncObfuscation := false
		for _, line := range strings.Split(content, "\n") {
			if !strings.Contains(strings.ToLower(line), "call_user_func") {
				continue
			}
			for _, targetArg := range phpCallUserFuncTargetArgs(line) {
				// PHP 7+ accepts both "\xNN" hex and "\u{NN}" unicode-codepoint
				// escapes inside double-quoted strings. Treat them as
				// equivalent obfuscation forms so an attacker cannot bypass
				// the detector by swapping syntax.
				lineHex := countOccurrences(targetArg, `"\x`) + countOccurrences(targetArg, `"\u{`)
				lineConcat := countOccurrences(targetArg, `" . "`) + countOccurrences(targetArg, `"."`)
				// Typical shortest obfuscated name is 3-4 bytes ("exec", "curl",
				// "eval"); require >=3 escapes AND >=2 concatenations on the
				// call target argument.
				if lineHex >= 3 && lineConcat >= 2 {
					indicators = append(indicators, "call_user_func with obfuscated function names")
					foundCallUserFuncObfuscation = true
					break
				}
			}
			if foundCallUserFuncObfuscation {
				break
			}
		}
	}

	// --- High: Goto obfuscation (LEVIATHAN signature) ---
	gotoCount := countOccurrences(contentLower, "goto ")
	if gotoCount > 10 {
		indicators = append(indicators, fmt.Sprintf("excessive goto statements (%d found - obfuscation pattern)", gotoCount))
	}

	// --- High: Hex-encoded string construction ---
	// Only flag hex strings when accompanied by concatenation - real obfuscation
	// builds function names like "\x63" . "\x75" . "\x72" . "\x6c" (= "curl").
	// Standalone hex arrays (Wordfence IPv6 subnet masks, binary data) are benign.
	hexStringCount := countOccurrences(content, `"\x`)
	dotConcatCount := countOccurrences(content, `" . "`)
	if hexStringCount > 20 && dotConcatCount > 10 {
		indicators = append(indicators, fmt.Sprintf("heavy hex-encoded strings with concatenation (%d hex, %d concat - obfuscation pattern)", hexStringCount, dotConcatCount))
	}
	// The standalone "concat>30 alone" branch was removed: WordPress
	// themes and page builders concatenate literal CSS/HTML tokens
	// dozens of times in dynamic style/markup builders (sydney theme,
	// elementor, beaver builder), producing FPs on every install. Real
	// function-name obfuscation always pairs concat with hex escapes
	// and is still caught by the combined branch above.

	// --- Critical: variable-function indirection that resolves to a
	// decoder. Attackers slip past the literal "eval(base64_decode("
	// detector by binding the dangerous name to a variable on one line
	// and calling it on another:
	//     $d = "base64_decode";
	//     $r = "eval";
	//     $r($d("AAAA"));
	// The heuristic looks for an assignment $var = "decoder_or_exec"
	// followed by a $var( invocation in the same file. Hits must
	// reference at least one decoder OR one shell-exec primitive,
	// since plain variable function calls show up in legitimate
	// metaprogramming.
	if detectVarFuncDangerousAssignment(content) {
		indicators = append(indicators, "variable function name resolves to decoder or exec primitive")
	}

	// --- High: Variable function calls with obfuscated names ---
	// call_user_func + decoder alone is too broad - Elementor, WooCommerce, and
	// dozens of plugins use call_user_func_array with base64_decode legitimately.
	// Only flag when combined with hex-built callable target obfuscation.
	if strings.Contains(contentLower, "call_user_func") && hasDecoder {
		if hasCallUserFuncHexNameBuild(content) {
			indicators = append(indicators, "variable function call with decoder and obfuscation")
		}
	}

	// --- High: Shell execution functions combined with request input ---
	// Uses containsStandaloneFunc to avoid substring false positives
	// (e.g. "WP_Filesystem(" matching "exec(", "preg_match(" matching "exec(")
	shellFuncs := []string{"system(", "passthru(", "exec(", "shell_exec(", "popen(", "proc_open(", "pcntl_exec("}
	// Two-tier detection:
	// Same line = CRITICAL signal (auto-quarantine eligible)
	// Co-presence = HIGH signal (alert only, not quarantined alone)
	// This prevents bypass by splitting across lines while avoiding
	// false-positive quarantine of legitimate plugins.
	hasShellFunc := false
	sameLineShellRequest := false
	for _, sf := range shellFuncs {
		if containsStandaloneFunc(contentLower, sf) {
			hasShellFunc = true
			break
		}
	}
	hasRequestVar := containsRequestSuperglobal(contentLower)
	// Same-line is a strong signal on its own: "$ret = system($_POST['cmd']);"
	// almost never occurs in legitimate code. Co-presence is weaker: elFinder
	// and other media-processing libraries legitimately call exec() for
	// ImageMagick and also consume $_POST for AJAX routing, placing both
	// tokens in the same 32 KB window. The co-presence finding is therefore
	// only emitted as CORROBORATION after all the stronger indicators have
	// been collected -- see the deferred append further below.
	coPresenceCandidate := false
	if hasShellFunc && hasRequestVar {
		for _, line := range strings.Split(contentLower, "\n") {
			lineHasShell := false
			for _, sf := range shellFuncs {
				if containsStandaloneFunc(line, sf) {
					lineHasShell = true
					break
				}
			}
			if !lineHasShell {
				continue
			}
			if containsRequestSuperglobal(line) {
				sameLineShellRequest = true
				break
			}
		}
		if sameLineShellRequest {
			indicators = append(indicators, "shell function with request input on same line")
		} else if !IsVerifiedCMSFile(path) {
			coPresenceCandidate = true
		}
	}

	// --- High: base64 encoding/decoding with execution on same line ---
	if strings.Contains(contentLower, "base64_decode") && strings.Contains(contentLower, "base64_encode") {
		for _, line := range strings.Split(contentLower, "\n") {
			hasBoth := strings.Contains(line, "base64_decode") && strings.Contains(line, "base64_encode")
			hasExec := false
			for _, sf := range shellFuncs {
				if containsStandaloneFunc(line, sf) {
					hasExec = true
					break
				}
			}
			if hasBoth && hasExec {
				indicators = append(indicators, "base64 encode+decode with execution on same line (command relay)")
				break
			}
		}
	}

	// Deferred corroboration: a lone co-presence is not enough. If a
	// stronger indicator was produced above, the co-presence is appended
	// both as extra context for the operator and to nudge the severity
	// into the >=2 Critical band for obfuscated droppers.
	if coPresenceCandidate && len(indicators) > 0 {
		indicators = append(indicators, "shell function co-present with request input")
	}

	// --- Determine severity based on indicators ---
	if len(indicators) == 0 {
		return phpAnalysisResult{severity: -1, readOK: readOK}
	}

	// Auto-quarantine in autoresponse.AutoQuarantineFiles acts only on
	// Critical findings. A single heuristic indicator has false-positive
	// classes severe enough to rm live production files (WPML's PHPZip
	// tripped the former "call_user_func with obfuscated" bypass on hex
	// constants that build ZIP magic bytes; legitimate plugins embed
	// pastebin URLs in support docstrings and release notes). Require
	// two converging indicators before the severity crosses the
	// destructive-action threshold; single hits surface as High and stay
	// in the operator queue.
	if len(indicators) >= 2 {
		return phpAnalysisResult{
			severity: alert.Critical,
			check:    "obfuscated_php",
			message:  "Obfuscated/malicious PHP detected",
			details:  fmt.Sprintf("Indicators found:\n- %s", strings.Join(indicators, "\n- ")),
			readOK:   true,
		}
	}

	return phpAnalysisResult{
		severity: alert.High,
		check:    "suspicious_php_content",
		message:  "Suspicious PHP content detected",
		details:  fmt.Sprintf("Indicators found:\n- %s", strings.Join(indicators, "\n- ")),
		readOK:   true,
	}
}

func countOccurrences(s, substr string) int {
	count := 0
	offset := 0
	for {
		idx := strings.Index(s[offset:], substr)
		if idx < 0 {
			break
		}
		count++
		offset += idx + len(substr)
	}
	return count
}

type hexNameAssignment struct {
	obfuscated bool
	hexEscapes int
	concatOps  int
	pos        int
}

func hasCallUserFuncHexNameBuild(content string) bool {
	code := stripPHPCommentsFromCode(content)
	assignments := findHexNameAssignments(code)
	searchFrom := 0
	for {
		callStart, openParen, closeParen, ok := nextStandalonePHPCall(code, searchFrom, callUserFuncCallNames)
		if !ok {
			return false
		}
		arg, argOK := firstPHPCallArgument(code, openParen+1)
		if argOK && phpExprHasHexNameBuild(arg) {
			return true
		}
		if argOK {
			if variable, varOK := singlePHPVariableExpr(arg); varOK && hexNameBuildAt(assignments[variable], callStart) {
				return true
			}
		}
		searchFrom = nextSearchOffset(closeParen, len(code))
	}
}

func findHexNameAssignments(code string) map[string][]hexNameAssignment {
	assignments := map[string][]hexNameAssignment{}
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
		j := skipPHPWhitespace(code, next)
		opLen, directAssign, appendAssign, ok := phpAssignmentOperator(code, j)
		if !ok {
			i = next - 1
			continue
		}

		exprStart := skipPHPWhitespace(code, j+opLen)
		exprEnd := phpExpressionEnd(code, exprStart)
		hexEscapes := 0
		concatOps := 0
		if directAssign || appendAssign {
			hexEscapes = countPHPStringHexEscapes(code[exprStart:exprEnd])
			concatOps = countPHPConcatOperators(code[exprStart:exprEnd])
		}
		if appendAssign {
			prev := lastHexNameAssignment(assignments[variable])
			hexEscapes += prev.hexEscapes
			concatOps += prev.concatOps + 1
		}
		assignments[variable] = append(assignments[variable], hexNameAssignment{
			obfuscated: phpExprCountsHaveHexNameBuild(hexEscapes, concatOps),
			hexEscapes: hexEscapes,
			concatOps:  concatOps,
			pos:        exprEnd,
		})
		i = next - 1
	}
	return assignments
}

func phpAssignmentOperator(code string, pos int) (int, bool, bool, bool) {
	if pos >= len(code) {
		return 0, false, false, false
	}
	if code[pos] == '=' && (pos+1 >= len(code) || (code[pos+1] != '=' && code[pos+1] != '>')) {
		return 1, true, false, true
	}
	if pos+1 < len(code) && code[pos] == '.' && code[pos+1] == '=' {
		return 2, false, true, true
	}
	if pos+1 < len(code) && strings.ContainsRune("+-*/%&|^", rune(code[pos])) && code[pos+1] == '=' {
		return 2, false, false, true
	}
	if pos+2 < len(code) {
		op := code[pos : pos+3]
		if op == "??=" || op == "<<=" || op == ">>=" {
			return 3, false, false, true
		}
	}
	return 0, false, false, false
}

func lastHexNameAssignment(assignments []hexNameAssignment) hexNameAssignment {
	if len(assignments) == 0 {
		return hexNameAssignment{}
	}
	return assignments[len(assignments)-1]
}

func hexNameBuildAt(assignments []hexNameAssignment, callPos int) bool {
	var last hexNameAssignment
	found := false
	for _, assignment := range assignments {
		if assignment.pos > callPos {
			break
		}
		last = assignment
		found = true
	}
	return found && last.obfuscated
}

func singlePHPVariableExpr(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || expr[0] != '$' {
		return "", false
	}
	variable, next, ok := readPHPVariableName(expr, 0)
	if !ok || skipPHPWhitespace(expr, next) != len(expr) {
		return "", false
	}
	return variable, true
}

func phpExprHasHexNameBuild(expr string) bool {
	return phpExprCountsHaveHexNameBuild(countPHPStringHexEscapes(expr), countPHPConcatOperators(expr))
}

func phpExprCountsHaveHexNameBuild(hexEscapes, concatOps int) bool {
	return hexEscapes >= 3 && concatOps >= 2
}

func countPHPStringHexEscapes(expr string) int {
	count := 0
	for i := 0; i < len(expr); i++ {
		if expr[i] != '"' {
			if isPHPQuote(expr[i]) {
				i = skipPHPString(expr, i)
			}
			continue
		}
		end := skipPHPString(expr, i)
		if end > i {
			literal := strings.ToLower(expr[i+1 : end])
			count += countOccurrences(literal, `\x`)
			count += countOccurrences(literal, `\u{`)
		}
		i = end
	}
	return count
}

func countPHPConcatOperators(expr string) int {
	count := 0
	for i := 0; i < len(expr); i++ {
		if isPHPQuote(expr[i]) {
			i = skipPHPString(expr, i)
			continue
		}
		if expr[i] == '.' {
			count++
		}
	}
	return count
}

func phpCallUserFuncTargetArgs(line string) []string {
	lower := strings.ToLower(line)
	var args []string
	for _, name := range []string{"call_user_func_array", "call_user_func"} {
		searchFrom := 0
		for {
			pos := strings.Index(lower[searchFrom:], name)
			if pos < 0 {
				break
			}
			pos += searchFrom
			next := pos + len(name)
			searchFrom = next
			if !isPHPFuncNameBoundary(line, pos, next) {
				continue
			}
			i := skipPHPSpaceString(line, next)
			if i >= len(line) || line[i] != '(' {
				continue
			}
			if arg, ok := firstPHPCallArgument(line, i+1); ok {
				args = append(args, arg)
			}
		}
	}
	return args
}

func isPHPFuncNameBoundary(s string, start, end int) bool {
	if start > 0 {
		prev := s[start-1]
		if isIdentCont(prev) || prev == '>' || prev == ':' {
			return false
		}
	}
	return end >= len(s) || !isIdentCont(s[end])
}

func skipPHPSpaceString(s string, i int) int {
	for i < len(s) && isPHPSpace(s[i]) {
		i++
	}
	return i
}

func firstPHPCallArgument(s string, start int) (string, bool) {
	start = skipPHPSpaceString(s, start)
	i := start
	depth := 0
	var quote byte
	escaped := false
	for i < len(s) {
		c := s[i]
		if quote != 0 {
			if escaped {
				escaped = false
				i++
				continue
			}
			if c == '\\' {
				escaped = true
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			i++
			continue
		}

		switch c {
		case '"', '\'':
			quote = c
		case '(', '[', '{':
			depth++
		case ')':
			if depth == 0 {
				return s[start:i], true
			}
			depth--
		case ',':
			if depth == 0 {
				return s[start:i], true
			}
		}
		i++
	}
	return "", false
}

// containsStandaloneFunc reports whether content contains an occurrence of
// funcCall (e.g. "exec(") that is a real call to the named PHP function
// rather than something that shares the same suffix.
//
// Four shapes must be rejected:
//
//   - embedded identifiers: "doubleval(" must not match "eval("; the
//     preceding character is a letter/digit/underscore;
//   - method invocations: "$this->DB->exec(" must not match "exec(" even
//     though the preceding ">" is non-alphanumeric;
//   - static invocations: "Foo::exec(" must not match for the same reason;
//   - function declarations: "function exec(" names a local function of
//     the same name and must not be counted as a call site.
//
// The earlier implementation only guarded against the first case and was
// the source of false positives on elFinder volume drivers that call
// "$this->DB->exec(...)" (SQLite) alongside $_SERVER references on the
// same line.
func containsStandaloneFunc(content, funcCall string) bool {
	idx := 0
	for {
		pos := strings.Index(content[idx:], funcCall)
		if pos < 0 {
			return false
		}
		absPos := idx + pos
		nextIdx := absPos + len(funcCall)

		advance := func() bool {
			if nextIdx >= len(content) {
				return false
			}
			idx = nextIdx
			return true
		}

		if absPos == 0 {
			return true
		}

		prev := content[absPos-1]
		isAlnum := (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') ||
			(prev >= '0' && prev <= '9') || prev == '_'
		if isAlnum {
			if !advance() {
				return false
			}
			continue
		}

		if absPos >= 2 {
			op := content[absPos-2 : absPos]
			if op == "->" || op == "::" {
				if !advance() {
					return false
				}
				continue
			}
		} else if absPos == 1 && (prev == '>' || prev == ':') {
			// Degenerate position: only one preceding byte, and it is
			// the tail char of a possible method ("->") or static
			// ("::") operator. We cannot confirm the second char
			// because there is no second char. The conservative choice
			// is to skip, so a truncated "->exec(" or "::exec(" at the
			// very start of a buffer does not get flagged as a real
			// shell-function call.
			if !advance() {
				return false
			}
			continue
		}
		const decl = "function "
		if absPos >= len(decl) && content[absPos-len(decl):absPos] == decl {
			if !advance() {
				return false
			}
			continue
		}

		return true
	}
}

func containsAny(strs []string, substrs ...string) bool {
	for _, s := range strs {
		for _, sub := range substrs {
			if strings.Contains(s, sub) {
				return true
			}
		}
	}
	return false
}

// benignPHPStubMaxScan caps how many bytes of a candidate stub the
// recogniser will read. Stub files in the wild (BackWPup folder.php
// caches at ~160 KB, WP "silence is golden" index.php at ~30 B, plugin
// 404-stub headers under 1 KB) fit comfortably under this bound;
// anything larger must surface for normal alerting rather than be
// accepted on faith.
const benignPHPStubMaxScan = 4 * 1024 * 1024

// IsBenignPHPStub reports whether the reachable code region of a PHP
// file consists only of whitespace and comments, or terminates with a
// no-argument die / exit / __halt_compiler before any other statement.
// Files matching either shape cannot execute attacker-controlled code
// via a web request: PHP either runs to EOF emitting nothing, or hits
// the terminator and stops with the remaining bytes unreachable.
//
// The recogniser is content-shape only -- it does not look at the path,
// filename, parent directory, or whether a plugin is installed. An
// attacker cannot bypass it by naming a payload to mimic a known-plugin
// file because the gate fails the moment any executable statement
// appears before a terminator. Conversely a legitimate plugin that
// writes a stub-shaped working file (BackWPup writes
// "<?php //<json>" for job state and "<?php\n//path1\n//path2..." for
// folder caches) is recognised regardless of where it puts the file.
//
// Other detectors -- signature scans, YARA, suspicious filename, the
// webshell name list -- still run on the file in their own pipelines.
// Only the path-only "anomalous PHP location" warning is suppressed
// for files that this recogniser accepts.
func IsBenignPHPStub(path string) bool {
	f, err := osFS.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, benignPHPStubMaxScan)
	n, _ := f.Read(buf)
	if n == 0 {
		return false
	}
	info, err := f.Stat()
	complete := err == nil && info.Size() <= int64(n)
	return IsBenignPHPStubBytesComplete(buf[:n], complete)
}

// IsBenignPHPStubBytes is the buffer-only variant. The realtime fanotify
// path uses it on the bytes it already read from the file descriptor;
// IsBenignPHPStub provides the path-based entry point for the polled
// fileindex scan. Both rely on the same parser so realtime and scheduled
// scans agree on which files are stubs.
//
// The parser tokenises the leading region of the buffer:
//
//   - Optional UTF-8 BOM and whitespace, then the literal "<?php" opener.
//     The short-echo opener "<?=" is rejected because it emits output.
//     A "<?phpfoo" run-together opener is rejected because PHP requires
//     whitespace (or EOF) after the tag.
//   - Repeatedly accept whitespace, line comments ("//..." or "#..." up to
//     newline or "?>"), and balanced block comments ("/* ... */"). A "/*"
//     without a matching "*/" inside the scanned window is rejected -- we
//     cannot prove the rest of the file is comment.
//   - Accept the no-argument forms of die, exit, and __halt_compiler as
//     terminators. Once seen, the rest of the buffer is treated as
//     unreachable.
//   - Reject any closing "?>" tag (would allow HTML escape and a later
//     "<?php" re-entry that this gate does not analyse).
//   - Reject any other identifier (return, if, system, eval, function,
//     class, ...) and any stray punctuation ("$", "(", "=", ";", ...).
//     Those are statements we cannot prove benign.
//   - If the loop reaches EOF in a complete buffer having only seen
//     whitespace and comments, accept: PHP outputs nothing and executes
//     nothing.
func IsBenignPHPStubBytes(buf []byte) bool {
	return IsBenignPHPStubBytesComplete(buf, true)
}

// IsBenignPHPStubBytesComplete is like IsBenignPHPStubBytes, but complete
// tells the parser whether buf contains the entire file. Comment-only stubs
// require a complete buffer; no-argument terminators do not, because bytes
// after them are unreachable to PHP.
func IsBenignPHPStubBytesComplete(buf []byte, complete bool) bool {
	if len(buf) >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF {
		buf = buf[3:]
	}
	i := 0
	for i < len(buf) && isPHPSpace(buf[i]) {
		i++
	}
	const opener = "<?php"
	if !bytes.HasPrefix(buf[i:], []byte(opener)) {
		return false
	}
	i += len(opener)
	if i < len(buf) && !isPHPSpace(buf[i]) {
		return false
	}
	for i < len(buf) {
		c := buf[i]
		if isPHPSpace(c) {
			i++
			continue
		}
		if c == '#' {
			i = skipPHPLineComment(buf, i)
			continue
		}
		if c == '/' && i+1 < len(buf) && buf[i+1] == '/' {
			i = skipPHPLineComment(buf, i)
			continue
		}
		if c == '/' && i+1 < len(buf) && buf[i+1] == '*' {
			i += 2
			end := bytes.Index(buf[i:], []byte("*/"))
			if end < 0 {
				return false
			}
			i += end + 2
			continue
		}
		if c == '?' && i+1 < len(buf) && buf[i+1] == '>' {
			return false
		}
		if isIdentStart(c) {
			start := i
			for i < len(buf) && isIdentCont(buf[i]) {
				i++
			}
			word := strings.ToLower(string(buf[start:i]))
			return isNoArgPHPTerminator(buf, i, word, complete)
		}
		return false
	}
	return complete
}

func isPHPSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentCont(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func skipPHPSpace(buf []byte, i int) int {
	for i < len(buf) && isPHPSpace(buf[i]) {
		i++
	}
	return i
}

func skipPHPLineComment(buf []byte, i int) int {
	for i < len(buf) {
		if buf[i] == '\n' {
			return i
		}
		if buf[i] == '?' && i+1 < len(buf) && buf[i+1] == '>' {
			return i
		}
		i++
	}
	return i
}

func isNoArgPHPTerminator(buf []byte, i int, word string, complete bool) bool {
	if word != "die" && word != "exit" && word != "__halt_compiler" {
		return false
	}
	i = skipPHPSpace(buf, i)

	if word == "__halt_compiler" {
		next, ok := consumeEmptyPHPParens(buf, i)
		if !ok {
			return false
		}
		return phpTerminatorStatementEnds(buf, next, complete)
	}

	if i >= len(buf) {
		return complete
	}
	if buf[i] == ';' {
		return true
	}
	if buf[i] == '?' && i+1 < len(buf) && buf[i+1] == '>' {
		return true
	}
	if buf[i] != '(' {
		return false
	}
	next, ok := consumeEmptyPHPParens(buf, i)
	if !ok {
		return false
	}
	return phpTerminatorStatementEnds(buf, next, complete)
}

func consumeEmptyPHPParens(buf []byte, i int) (int, bool) {
	if i >= len(buf) || buf[i] != '(' {
		return i, false
	}
	i = skipPHPSpace(buf, i+1)
	if i >= len(buf) || buf[i] != ')' {
		return i, false
	}
	return skipPHPSpace(buf, i+1), true
}

func phpTerminatorStatementEnds(buf []byte, i int, complete bool) bool {
	i = skipPHPSpace(buf, i)
	if i >= len(buf) {
		return complete
	}
	if buf[i] == ';' {
		return true
	}
	return buf[i] == '?' && i+1 < len(buf) && buf[i+1] == '>'
}
