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
	// code, however large the tail is. Plugins that keep state in .php files
	// (WAF configs, attack logs) rewrite these constantly.
	return checks.PHPTerminatesImmediately(c.Head)
}

// dropperContentIsInert only exempts complete blank content. PHP can decode
// source before tokenization, including transfer encodings such as Base64
// and quoted-printable. Even ASCII text that resembles a comment can contain
// statements after that conversion. Without the interpreter's effective
// encoding settings, a PHP comment parser cannot prove those files inert.
func dropperContentIsInert(head []byte, size int64) bool {
	return size >= 0 && size <= int64(len(head)) && strings.Trim(string(head), " \t\r\n") == ""
}
