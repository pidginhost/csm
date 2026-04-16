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

// isCpanelManagedUserIni reports whether data begins with the cPanel
// MultiPHP-managed .user.ini header. Empty/whitespace-only input
// returns false. Leading blank lines are skipped before the check.
func isCpanelManagedUserIni(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Walk lines until the first non-blank one is found. Check that
	// line for the signature and return immediately. If we never find
	// a non-blank line, the file is considered unmanaged.
	start := 0
	for i := 0; i <= len(data); i++ {
		if i < len(data) && data[i] != '\n' {
			continue
		}
		line := data[start:i]
		// Strip CR from CRLF, then whitespace on both sides.
		line = bytes.TrimRight(line, "\r")
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			return bytes.Contains(line, []byte(cpanelUserIniSignature))
		}
		start = i + 1
	}
	return false
}
