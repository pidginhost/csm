package checks

import (
	"strings"
)

type indirectFuncKind uint8

const (
	indirectDecoder indirectFuncKind = 1 << iota
	indirectEval
	indirectShell
)

var indirectFuncKinds = map[string]indirectFuncKind{
	"base64_decode":   indirectDecoder,
	"gzinflate":       indirectDecoder,
	"gzuncompress":    indirectDecoder,
	"gzdecode":        indirectDecoder,
	"bzdecompress":    indirectDecoder,
	"str_rot13":       indirectDecoder,
	"rawurldecode":    indirectDecoder,
	"eval":            indirectEval,
	"assert":          indirectEval,
	"create_function": indirectEval,
	"system":          indirectShell,
	"passthru":        indirectShell,
	"exec":            indirectShell,
	"shell_exec":      indirectShell,
	"popen":           indirectShell,
	"proc_open":       indirectShell,
	"pcntl_exec":      indirectShell,
}

type indirectAssignment struct {
	kind indirectFuncKind
	pos  int
}

type indirectCall struct {
	variable  string
	kind      indirectFuncKind
	pos       int
	lineStart int
	lineEnd   int
	line      string
}

// detectVarFuncDangerousAssignment returns true when content contains a
// `$var = "dangerous_name"` assignment followed by a corresponding
// `$var(` invocation that forms an execution sink. Decoder-only
// callbacks are not enough; direct base64_decode() calls are common in
// legitimate plugins, and indirect callbacks need the same restraint.
func detectVarFuncDangerousAssignment(content string) bool {
	code := stripPHPCommentsFromCode(content)
	assignments := findIndirectAssignments(code)
	if len(assignments) == 0 {
		return false
	}
	calls := findIndirectCalls(code, assignments)
	if len(calls) == 0 {
		return false
	}

	for _, call := range calls {
		switch {
		case call.kind&indirectShell != 0:
			if lineContainsRequestVar(call.line) {
				return true
			}
		case call.kind&indirectEval != 0:
			if lineContainsRequestVar(call.line) ||
				lineContainsDirectDecoderCall(call.line) ||
				lineContainsIndirectCallKind(calls, call.lineStart, call.lineEnd, indirectDecoder) {
				return true
			}
		case call.kind&indirectDecoder != 0:
			if lineContainsDirectEvalCall(call.line) ||
				lineContainsIndirectCallKind(calls, call.lineStart, call.lineEnd, indirectEval) {
				return true
			}
		}
	}
	return false
}

func findIndirectAssignments(code string) map[string][]indirectAssignment {
	assignments := map[string][]indirectAssignment{}
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
		if j >= len(code) || code[j] != '=' || (j+1 < len(code) && (code[j+1] == '=' || code[j+1] == '>')) {
			i = next - 1
			continue
		}

		assignment := indirectAssignment{pos: j + 1}
		valueStart := skipPHPWhitespace(code, j+1)
		if valueStart < len(code) && isPHPQuote(code[valueStart]) {
			value, valueEnd, valueOK := readPHPFunctionString(code, valueStart)
			assignment.pos = valueEnd
			if valueOK {
				assignment.kind = indirectFuncKinds[value]
			}
		}
		assignments[variable] = append(assignments[variable], assignment)
		i = next - 1
	}
	return assignments
}

func findIndirectCalls(code string, assignments map[string][]indirectAssignment) []indirectCall {
	var calls []indirectCall
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
		if j >= len(code) || code[j] != '(' {
			i = next - 1
			continue
		}
		kind, ok := indirectKindAt(assignments[variable], i)
		if !ok {
			i = next - 1
			continue
		}
		lineStart, lineEnd := phpLineBounds(code, i)
		calls = append(calls, indirectCall{
			variable:  variable,
			kind:      kind,
			pos:       i,
			lineStart: lineStart,
			lineEnd:   lineEnd,
			line:      code[lineStart:lineEnd],
		})
		i = next - 1
	}
	return calls
}

func indirectKindAt(assignments []indirectAssignment, callPos int) (indirectFuncKind, bool) {
	var last indirectFuncKind
	found := false
	for _, assignment := range assignments {
		if assignment.pos > callPos {
			break
		}
		last = assignment.kind
		found = true
	}
	return last, found && last != 0
}

func lineContainsDirectDecoderCall(line string) bool {
	codeLine := strings.ToLower(stripPHPStringsFromCode(line))
	for name, kind := range indirectFuncKinds {
		if kind&indirectDecoder != 0 && containsStandaloneFunc(codeLine, name+"(") {
			return true
		}
	}
	return false
}

func lineContainsDirectEvalCall(line string) bool {
	codeLine := strings.ToLower(stripPHPStringsFromCode(line))
	for name, kind := range indirectFuncKinds {
		if kind&indirectEval != 0 && containsStandaloneFunc(codeLine, name+"(") {
			return true
		}
	}
	return false
}

func lineContainsRequestVar(line string) bool {
	return containsRequestSuperglobal(stripPHPStringsFromCode(line))
}

func lineContainsIndirectCallKind(calls []indirectCall, lineStart, lineEnd int, kind indirectFuncKind) bool {
	for _, call := range calls {
		if call.lineStart == lineStart && call.lineEnd == lineEnd && call.kind&kind != 0 {
			return true
		}
	}
	return false
}

func stripPHPCommentsFromCode(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	for i := 0; i < len(code); i++ {
		// Heredoc/nowdoc bodies are string literals, not code. Copy them
		// verbatim so a '#', '//', or '/*' inside the body is not mistaken
		// for a comment (which would corrupt the surrounding code).
		if label, bodyStart, ok := phpHeredocOpen(code, i); ok {
			end := phpHeredocEnd(code, bodyStart, label)
			b.WriteString(code[i:end])
			i = end - 1
			continue
		}
		if isPHPQuote(code[i]) {
			i = copyPHPString(&b, code, i)
			continue
		}
		if code[i] == '/' && i+1 < len(code) && code[i+1] == '*' {
			b.WriteString("  ")
			i += 2
			for i < len(code) {
				if code[i] == '*' && i+1 < len(code) && code[i+1] == '/' {
					b.WriteString("  ")
					i++
					break
				}
				writeCommentReplacementByte(&b, code[i])
				i++
			}
			continue
		}
		if code[i] == '/' && i+1 < len(code) && code[i+1] == '/' {
			b.WriteString("  ")
			i += 2
			for i < len(code) {
				if code[i] == '\n' || code[i] == '\r' {
					b.WriteByte(code[i])
					break
				}
				b.WriteByte(' ')
				i++
			}
			continue
		}
		if code[i] == '#' {
			b.WriteByte(' ')
			i++
			for i < len(code) {
				if code[i] == '\n' || code[i] == '\r' {
					b.WriteByte(code[i])
					break
				}
				b.WriteByte(' ')
				i++
			}
			continue
		}
		b.WriteByte(code[i])
	}
	return b.String()
}

func stripPHPStringsFromCode(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	for i := 0; i < len(code); i++ {
		// Blank heredoc/nowdoc bodies (and their opener/closing label) the same
		// way single/double-quoted strings are blanked, so their contents are
		// not analysed as code and a quote inside the body cannot desync the
		// scanner and swallow real code that follows the heredoc.
		if label, bodyStart, ok := phpHeredocOpen(code, i); ok {
			end := phpHeredocEnd(code, bodyStart, label)
			for k := i; k < end; k++ {
				if code[k] == '\n' || code[k] == '\r' {
					b.WriteByte(code[k])
				} else {
					b.WriteByte(' ')
				}
			}
			i = end - 1
			continue
		}
		if isPHPQuote(code[i]) {
			i = replacePHPString(&b, code, i)
			continue
		}
		b.WriteByte(code[i])
	}
	return b.String()
}

// phpHeredocOpen reports whether code[i:] opens a heredoc or nowdoc. On success
// it returns the label and the byte index where the body begins (just past the
// opening line's newline). It recognises `<<<LABEL`, `<<<"LABEL"` (heredoc) and
// `<<<'LABEL'` (nowdoc), with optional spaces/tabs after `<<<`.
func phpHeredocOpen(code string, i int) (label string, bodyStart int, ok bool) {
	if i+3 > len(code) || code[i] != '<' || code[i+1] != '<' || code[i+2] != '<' {
		return "", 0, false
	}
	if i > 0 && code[i-1] == '<' {
		return "", 0, false
	}
	j := i + 3
	for j < len(code) && (code[j] == ' ' || code[j] == '\t') {
		j++
	}
	var quote byte
	if j < len(code) && (code[j] == '\'' || code[j] == '"') {
		quote = code[j]
		j++
	}
	if j >= len(code) || !isPHPIdentifierStart(code[j]) {
		return "", 0, false
	}
	start := j
	j++
	for j < len(code) && isPHPIdentifierPart(code[j]) {
		j++
	}
	label = code[start:j]
	if quote != 0 {
		if j >= len(code) || code[j] != quote {
			return "", 0, false
		}
		j++
	}
	// The opening line ends at the next newline; only trailing whitespace and
	// an optional CR may sit between the label and that newline.
	for j < len(code) && (code[j] == ' ' || code[j] == '\t' || code[j] == '\r') {
		j++
	}
	if j >= len(code) || code[j] != '\n' {
		return "", 0, false
	}
	return label, j + 1, true
}

// phpHeredocEnd returns the byte index just past the closing label of a heredoc
// whose body begins at bodyStart. PHP 7.3+ permits the closing label to be
// indented; the label must appear at the start of a line (after optional
// spaces/tabs) and be followed by a non-identifier byte. An unterminated
// heredoc consumes the rest of the input.
func phpHeredocEnd(code string, bodyStart int, label string) int {
	i := bodyStart
	for i < len(code) {
		lineEnd := i
		for lineEnd < len(code) && code[lineEnd] != '\n' {
			lineEnd++
		}
		k := i
		for k < lineEnd && (code[k] == ' ' || code[k] == '\t') {
			k++
		}
		if k+len(label) <= lineEnd && code[k:k+len(label)] == label {
			after := k + len(label)
			if after >= len(code) || !isPHPIdentifierPart(code[after]) {
				return after
			}
		}
		if lineEnd >= len(code) {
			break
		}
		i = lineEnd + 1
	}
	return len(code)
}

func copyPHPString(b *strings.Builder, code string, start int) int {
	quote := code[start]
	b.WriteByte(code[start])
	for i := start + 1; i < len(code); i++ {
		b.WriteByte(code[i])
		if code[i] == '\\' && i+1 < len(code) {
			i++
			b.WriteByte(code[i])
			continue
		}
		if code[i] == quote {
			return i
		}
	}
	return len(code) - 1
}

func replacePHPString(b *strings.Builder, code string, start int) int {
	quote := code[start]
	b.WriteByte(' ')
	for i := start + 1; i < len(code); i++ {
		if code[i] == '\n' || code[i] == '\r' {
			b.WriteByte(code[i])
		} else {
			b.WriteByte(' ')
		}
		if code[i] == '\\' && i+1 < len(code) {
			i++
			if code[i] == '\n' || code[i] == '\r' {
				b.WriteByte(code[i])
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		if code[i] == quote {
			return i
		}
	}
	return len(code) - 1
}

func writeCommentReplacementByte(b *strings.Builder, c byte) {
	if c == '\n' || c == '\r' {
		b.WriteByte(c)
		return
	}
	b.WriteByte(' ')
}

func readPHPVariableName(code string, dollar int) (string, int, bool) {
	if dollar+1 >= len(code) || !isPHPIdentifierStart(code[dollar+1]) {
		return "", dollar + 1, false
	}
	i := dollar + 2
	for i < len(code) && isPHPIdentifierPart(code[i]) {
		i++
	}
	return code[dollar+1 : i], i, true
}

func readPHPFunctionString(code string, start int) (string, int, bool) {
	quote := code[start]
	var b strings.Builder
	for i := start + 1; i < len(code); i++ {
		if code[i] == '\\' && i+1 < len(code) {
			if code[i+1] == quote || code[i+1] == '\\' {
				i++
				b.WriteByte(code[i])
				continue
			}
			b.WriteByte(code[i])
			continue
		}
		if code[i] == quote {
			value, ok := normalizeIndirectFunctionName(b.String())
			return value, i + 1, ok
		}
		b.WriteByte(code[i])
	}
	return "", len(code), false
}

func normalizeIndirectFunctionName(value string) (string, bool) {
	value = strings.TrimLeft(value, "\\")
	if !isPHPIdentifier(value) {
		return "", false
	}
	return strings.ToLower(value), true
}

func skipPHPString(code string, start int) int {
	quote := code[start]
	for i := start + 1; i < len(code); i++ {
		if code[i] == '\\' && i+1 < len(code) {
			i++
			continue
		}
		if code[i] == quote {
			return i
		}
	}
	return len(code) - 1
}

func skipPHPWhitespace(code string, start int) int {
	for start < len(code) {
		switch code[start] {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			start++
		default:
			return start
		}
	}
	return start
}

func phpLineBounds(code string, pos int) (int, int) {
	start := pos
	for start > 0 && code[start-1] != '\n' && code[start-1] != '\r' {
		start--
	}
	end := pos
	for end < len(code) && code[end] != '\n' && code[end] != '\r' {
		end++
	}
	return start, end
}

func isPHPQuote(c byte) bool {
	return c == '\'' || c == '"'
}

func isPHPIdentifier(value string) bool {
	if value == "" || !isPHPIdentifierStart(value[0]) {
		return false
	}
	for i := 1; i < len(value); i++ {
		if !isPHPIdentifierPart(value[i]) {
			return false
		}
	}
	return true
}

func isPHPIdentifierStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isPHPIdentifierPart(c byte) bool {
	return isPHPIdentifierStart(c) || (c >= '0' && c <= '9')
}
