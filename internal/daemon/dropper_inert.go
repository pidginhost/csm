package daemon

import "strings"

func dropperCandidateIsInert(c dropperCandidate) bool {
	// Executable files may be interpreted by a shell rather than PHP.
	// PHP comments do not prove that such a script has no commands.
	if c.Mode&0o111 != 0 {
		return c.Size >= 0 && c.Size <= int64(len(c.Head)) && strings.Trim(string(c.Head), " \t\n") == ""
	}
	return dropperContentIsInert(c.Head, c.Size)
}

// dropperContentIsInert only exempts complete blank content. PHP can decode
// source before tokenization, including transfer encodings such as Base64
// and quoted-printable. Even ASCII text that resembles a comment can contain
// statements after that conversion. Without the interpreter's effective
// encoding settings, a PHP comment parser cannot prove those files inert.
func dropperContentIsInert(head []byte, size int64) bool {
	return size >= 0 && size <= int64(len(head)) && strings.Trim(string(head), " \t\r\n") == ""
}
