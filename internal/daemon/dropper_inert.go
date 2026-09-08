package daemon

import "strings"

// dropperContentIsInert reports whether a file's complete contents contain no
// executable PHP statement.
//
// The dropper detector watches for "a PHP file appeared under a docroot and
// then vanished". WordPress and its plugins do that constantly with directory
// guard files, and on a production host one plugin's zero-byte index.php
// produced 778 findings in 30 hours -- enough to promote an ordinary account
// to a compromise incident.
//
// Content is the honest discriminator, not the path: allowlisting a path just
// tells an attacker where to work, while a file with no statement in it does
// nothing when included and so cannot be the payload half of a dropper. An
// attacker who removes the code from their dropper no longer has one.
//
// size guards the decision. The caller retains only a bounded head, and a
// comment at the top of a large file says nothing about the rest, so anything
// the head does not fully cover is treated as code-bearing.
func dropperContentIsInert(head []byte, size int64) bool {
	if size < 0 || size > int64(len(head)) {
		return false
	}

	rest := strings.TrimSpace(string(head))
	if rest == "" {
		return true
	}
	// Content outside a PHP tag is emitted, not executed, but it can still be
	// the data half of an include. Only a file that is nothing but an opening
	// tag and commentary is judged inert.
	if !strings.HasPrefix(rest, "<?php") {
		return false
	}
	rest = strings.TrimSpace(rest[len("<?php"):])

	for rest != "" {
		switch {
		case strings.HasPrefix(rest, "//"), strings.HasPrefix(rest, "#") && !strings.HasPrefix(rest, "#["):
			if i := strings.IndexByte(rest, '\n'); i >= 0 {
				rest = rest[i+1:]
			} else {
				rest = ""
			}
		case strings.HasPrefix(rest, "/*"):
			i := strings.Index(rest[2:], "*/")
			if i < 0 {
				// Unterminated comment: everything after it is commentary.
				rest = ""
				continue
			}
			rest = rest[2+i+2:]
		case strings.HasPrefix(rest, "?>"):
			// A closing tag ends the code section; whatever follows is output,
			// and output alone still executes nothing.
			rest = ""
		default:
			return false
		}
		rest = strings.TrimSpace(rest)
	}
	return true
}
