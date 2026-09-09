package daemon

import (
	"strings"

	"github.com/pidginhost/csm/internal/checks"
)

func dropperCandidateIsInert(c dropperCandidate) bool {
	// Executable files may be interpreted by a shell rather than PHP.
	// PHP comments do not prove that such a script has no commands.
	if c.Mode&0o111 != 0 {
		return c.Size >= 0 && c.Size <= int64(len(c.Head)) && strings.Trim(string(c.Head), " \t\n") == ""
	}
	if dropperContentIsInert(c.Head, c.Size) {
		return true
	}
	// A file whose first statement halts the interpreter carries data, not
	// code, however large the tail is. Plugins keep state and WAF data in
	// .php files of that shape and rewrite them constantly.
	//
	// Shift-based source encodings cannot reach this shape the way they reach
	// a comment: the accepted bytes are the opening tag, PHP whitespace, one
	// terminator keyword and a plain-ASCII literal with every encoding-shift
	// byte rejected, so an ASCII-transparent encoding leaves them unchanged
	// and a non-transparent one never matches the raw opening tag. A whole-file
	// transport encoding is the exception: under a BASE64 source encoding this
	// header is discarded as padding and an encoded tail becomes the program.
	// Refuse the exemption when the tail could be that, which costs at most a
	// plugin state file staying a candidate.
	end, ok := checks.PHPTerminatesImmediatelyAt(c.Head)
	return ok && !dropperTailCouldDecodeToSource(c.Head[end:])
}

// dropperTailCouldDecodeToSource reports whether the unreachable tail is made
// only of transport-encoding alphabet, which a source-encoding conversion
// could turn back into PHP. Real data files carry punctuation or text that no
// such alphabet contains.
func dropperTailCouldDecodeToSource(tail []byte) bool {
	digits := 0
	for _, b := range tail {
		switch {
		case b == ' ' || b == '\t' || b == '\n' || b == '\r':
		case (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '+' || b == '/' || b == '=' || b == '-' || b == '_':
			digits++
		default:
			return false
		}
	}
	// Eight alphabet characters carry the six bytes of a "<?php " opener.
	return digits >= 8
}

// dropperContentIsInert only exempts complete blank content. PHP can decode
// source before tokenization, including transfer encodings such as Base64
// and quoted-printable. Even ASCII text that resembles a comment can contain
// statements after that conversion. Without the interpreter's effective
// encoding settings, a PHP comment parser cannot prove those files inert.
func dropperContentIsInert(head []byte, size int64) bool {
	return size >= 0 && size <= int64(len(head)) && strings.Trim(string(head), " \t\r\n") == ""
}
