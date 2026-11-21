package checks

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aymanbagabas/go-udiff"
)

// The diff engine indexes individual lines as well as their byte offsets.
const maxPreviewLines = 64 * 1024
const maxPreviewBytes = 8 << 20

var errPreviewTooLarge = errors.New("content is too large to display as a diff")
var errPreviewBinary = errors.New("binary content cannot be shown as a diff")

func previewTooLarge(data []byte) bool {
	return len(data) > maxPreviewBytes || bytes.Count(data, []byte{'\n'}) > maxPreviewLines
}

// renderChangeDiff renders the change from before to after as a unified diff.
// Each file header carries the SHA-256 of its content, the digest the action
// log records, so a preview can be matched to the action that applied it.
func renderChangeDiff(path string, before, after []byte) (string, error) {
	if previewTooLarge(before) || previewTooLarge(after) {
		return "", errPreviewTooLarge
	}
	if looksBinary(before) || looksBinary(after) {
		return "", errPreviewBinary
	}
	// A newline in a tenant's file name must not forge a header line.
	label := DisplayField(path)
	old, changed := string(before), string(after)
	diff, err := udiff.ToUnified(label+"\tsha256:"+sha256Hex(before), label+"\tsha256:"+sha256Hex(after),
		old, udiff.Lines(old, changed), udiff.DefaultContextLines)
	if err != nil {
		return "", fmt.Errorf("rendering diff: %w", err)
	}
	return TerminalSafe(diff), nil
}

// DisplayField escapes a single untrusted value, including embedded line breaks.
func DisplayField(s string) string {
	quoted := strconv.Quote(s)
	return quoted[1 : len(quoted)-1]
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

// Alert diffs can leave the host. Show the appended deny rule with zero
// context. When apply terminates the last existing line, mask its contents
// on both sides and keep the missing-newline marker.
func renderAlertDenyDiff(path string, before, after, block []byte) (string, error) {
	if looksBinary(before) || looksBinary(after) {
		return "", errPreviewBinary
	}
	var b strings.Builder
	label := DisplayField(path)
	fmt.Fprintf(&b, "--- %s\tsha256:%s\n+++ %s\tsha256:%s\n", label, sha256Hex(before), label, sha256Hex(after))
	oldLines := bytes.Count(before, []byte{'\n'})
	added := bytes.Count(block, []byte{'\n'})
	if len(before) > 0 && before[len(before)-1] != '\n' {
		fmt.Fprintf(&b, "@@ -%d +%d,%d @@\n", oldLines+1, oldLines+1, added+1)
		b.WriteString("-[existing line omitted]\n\\ No newline at end of file\n+[existing line omitted]\n")
	} else {
		fmt.Fprintf(&b, "@@ -%d,0 +%d,%d @@\n", oldLines, oldLines+1, added)
	}
	for line := range strings.Lines(string(block)) {
		b.WriteByte('+')
		b.WriteString(TerminalSafe(line))
	}
	return b.String(), nil
}
