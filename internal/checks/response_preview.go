package checks

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aymanbagabas/go-udiff"
)

var errPreviewBinary = errors.New("binary content cannot be shown as a diff")

// renderChangeDiff renders the change from before to after as a unified diff.
// Each file header carries the SHA-256 of its content, the digest the action
// log records, so a preview can be matched to the action that applied it.
func renderChangeDiff(path string, before, after []byte) (string, error) {
	if looksBinary(before) || looksBinary(after) {
		return "", errPreviewBinary
	}
	// A newline in a tenant's file name must not forge a header line.
	label := strconv.Quote(path)
	label = label[1 : len(label)-1]
	old, changed := string(before), string(after)
	diff, err := udiff.ToUnified(label+"\tsha256:"+sha256Hex(before), label+"\tsha256:"+sha256Hex(after),
		old, udiff.Lines(old, changed), udiff.DefaultContextLines)
	if err != nil {
		return "", fmt.Errorf("rendering diff: %w", err)
	}
	return TerminalSafe(diff), nil
}

// TerminalSafe escapes everything in s an operator's terminal could act on:
// control characters other than newline and tab, invisible format characters
// such as bidi overrides, and invalid UTF-8.
func TerminalSafe(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\n' || r == '\t' || unicode.IsPrint(r):
			b.WriteString(s[i : i+size])
		default:
			quoted := strconv.QuoteRuneToASCII(r)
			b.WriteString(quoted[1 : len(quoted)-1])
		}
		i += size
	}
	return b.String()
}
