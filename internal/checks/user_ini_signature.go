package checks

import "bytes"

// .user.ini cPanel-managed signature detection.
//
// cPanel's MultiPHP INI Editor writes .user.ini files with a fixed
// four-line header that begins:
//
//   ; cPanel-generated php ini directives, do not edit
//   ; Manual editing of this file may result in unexpected behavior.
//   ; To make changes to this file, use the cPanel MultiPHP INI Editor ...
//   ; For more information, read our documentation ...
//
// When this header is present the values in the file reflect operator
// choices made through cPanel's UI (max_execution_time=0 for a backup
// importer, display_errors=On for a staging account, etc.). These are
// not attacker signals. The severity of findings on values in a
// cPanel-managed file should be reduced to informational.
//
// When the header is absent we cannot tell whether the site owner
// hand-edited the file or an attacker planted it. In that case we
// preserve the original severity.
//
// Detection rule (minimal and precise):
//
//   The signature must appear on the FIRST non-blank line of the file.
//
// Reasoning: cPanel always writes the header at the top of the file
// and rewrites the whole file on every edit through the UI. An
// attacker appending content below keeps the header position intact.
// An attacker prepending content above pushes the header down; the
// file is then no longer a regular cPanel-managed file and the
// attacker's values take precedence anyway — we must NOT accept this
// as "managed" because doing so would let attackers suppress findings
// by inserting one of their own lines and then the real cPanel header.

// cpanelUserIniSignature is the exact string cPanel writes on the first
// comment line of a managed .user.ini. Case-sensitive: alternate
// capitalizations are rejected to avoid accepting forgeries.
const cpanelUserIniSignature = "cPanel-generated php ini directives"

// cpanelUserIniMaxLeadingBlanks caps how many blank lines may precede
// the signature. cPanel itself writes the signature as the very first
// line, so any tolerance here is purely for admins who may have
// round-tripped the file through a text editor that adds a trailing
// newline or through an FTP client that accumulates CRLFs. A small cap
// also closes a forgery route: without a bound, an attacker who wants
// to suppress severity on their injected values could prepend a large
// run of blank lines followed by the genuine cPanel header string, and
// a first-non-blank-line-only check would classify the file as
// managed despite the attacker owning all the content above the
// header.
const cpanelUserIniMaxLeadingBlanks = 5

// isCpanelManagedUserIni reports whether data begins with the cPanel
// MultiPHP-managed .user.ini header. Empty/whitespace-only input
// returns false. A small number (cpanelUserIniMaxLeadingBlanks) of
// leading blank lines is tolerated; beyond that, the file is not
// considered cPanel-managed even if the signature appears later.
func isCpanelManagedUserIni(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	blanks := 0
	start := 0
	for i := 0; i <= len(data); i++ {
		if i < len(data) && data[i] != '\n' {
			continue
		}
		line := data[start:i]
		// Strip CR from CRLF, then whitespace on both sides.
		line = bytes.TrimRight(line, "\r")
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			blanks++
			if blanks > cpanelUserIniMaxLeadingBlanks {
				return false
			}
			start = i + 1
			continue
		}
		return bytes.Contains(line, []byte(cpanelUserIniSignature))
	}
	return false
}
