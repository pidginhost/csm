package checks

import (
	"context"
	"regexp"
	"strings"
)

var (
	wpMyISAMDefineStart = regexp.MustCompile(`(?i)\bdefine\s*\(`)
	wpMyISAMPrefixUse   = regexp.MustCompile(`\$table_prefix\b`)
)

func readWPMyISAMConfig(ctx context.Context, path string) (wpDBCreds, bool) {
	data, err := readCMSConfig(ctx, path)
	if err != nil {
		return wpDBCreds{}, false
	}
	return parseWPMyISAMConfig(data)
}

// Root's catalogue cannot verify a guessed scope by authenticating as the
// site. Require explicit literal settings instead of the shared credential
// parser's defaults, and never execute tenant PHP to resolve expressions.
func parseWPMyISAMConfig(data []byte) (wpDBCreds, bool) {
	code := stripPHPCommentsFromCode(phpCodeOnly(string(data)))
	masked := stripPHPStringsFromCode(code)
	topLevel := wpMyISAMStatementStarts(masked)
	values := make(map[string]string)
	seen := make(map[string]bool)
	valid := true
	for _, loc := range wpMyISAMDefineStart.FindAllStringIndex(masked, -1) {
		key, pos, ok := wpMyISAMLiteral(code, loc[1])
		if !ok || (key != "DB_NAME" && key != "DB_HOST") {
			continue
		}
		start := loc[0]
		if start > 0 && code[start-1] == '\\' {
			start--
		}
		pos, comma := wpMyISAMTake(code, pos, ',')
		value, pos, literal := wpMyISAMLiteral(code, pos)
		pos, closeParen := wpMyISAMTake(code, pos, ')')
		_, semicolon := wpMyISAMTake(code, pos, ';')
		if seen[key] || !topLevel[start] || !comma || !literal || !closeParen || !semicolon {
			valid = false
			values[key] = ""
		} else {
			values[key] = value
		}
		seen[key] = true
	}
	creds := wpDBCreds{dbName: values["DB_NAME"], dbHost: values["DB_HOST"]}
	// A second prefix reference may mutate it conditionally or pass it by
	// reference. Only a sole literal assignment establishes table ownership.
	uses := wpMyISAMPrefixUse.FindAllStringIndex(masked, -1)
	if len(uses) != 1 || !topLevel[uses[0][0]] {
		return creds, false
	}
	pos, equal := wpMyISAMTake(code, uses[0][1], '=')
	prefix, pos, literal := wpMyISAMLiteral(code, pos)
	_, semicolon := wpMyISAMTake(code, pos, ';')
	creds.tablePrefix = prefix
	prefixOK := prefix == "" || validTablePrefix.MatchString(prefix)
	return creds, valid && creds.dbName != "" && creds.dbHost != "" && equal && literal && semicolon && prefixOK
}

// Work on the string-masked code so punctuation in literals cannot turn a
// conditional assignment into an unconditional one. Record every position in
// one pass rather than rescanning the prefix for each candidate statement.
func wpMyISAMStatementStarts(masked string) []bool {
	starts := make([]bool, len(masked))
	depth := 0
	boundary := true
	for i := 0; i < len(masked); i++ {
		starts[i] = depth == 0 && boundary
		switch masked[i] {
		case ' ', '\t', '\r', '\n', '\v', '\f':
			continue
		case '(', '[', '{':
			depth++
			boundary = false
		case ')', ']', '}':
			depth--
			boundary = masked[i] == '}' && depth == 0
		case ';':
			boundary = depth == 0
		case ':':
			if depth == 0 {
				// Alternative control syntax has no braces. Subsequent
				// statements cannot be proved unconditional by this scanner.
				return starts
			}
			boundary = false
		default:
			boundary = false
		}
	}
	return starts
}

func wpMyISAMTake(code string, pos int, want byte) (int, bool) {
	pos = skipPHPWhitespace(code, pos)
	if pos == len(code) || code[pos] != want {
		return pos, false
	}
	return pos + 1, true
}

func wpMyISAMLiteral(code string, pos int) (string, int, bool) {
	pos = skipPHPWhitespace(code, pos)
	if pos == len(code) || (code[pos] != '\'' && code[pos] != '"') {
		return "", pos, false
	}
	end, closed := storedPHPStringClose(code, pos)
	if !closed || storedPHPStringInterpolates(code, pos, end) {
		return "", end, false
	}
	value := phpStringLiteralValue(code, pos, end)
	// Database settings never need embedded NULs, which cannot name a schema,
	// table or endpoint and would make scope keys ambiguous.
	return value, end + 1, !strings.ContainsRune(value, 0)
}
