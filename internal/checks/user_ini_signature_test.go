package checks

import (
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Contract for isCpanelManagedUserIni
//
// cPanel writes a stable header comment to .user.ini files it manages
// via the MultiPHP INI Editor. When that header is present the values
// inside the file reflect operator choices made through the cPanel UI
// — max_execution_time=0 for a backup-importer, display_errors=On for
// a staging environment, etc. These are not attacker signals.
//
// When the header is missing the file may have been hand-edited by the
// site owner OR written by an attacker; we cannot tell. The safe
// default is to keep the current severity.
//
// isCpanelManagedUserIni must:
//   - return true for the real cPanel header observed on cluster6
//     (captured verbatim below, including the license comment block);
//   - return true for minor variations of the header WordPress admins
//     routinely accumulate (trailing whitespace, extra blank lines);
//   - return false when the file has no such header, even if it
//     mentions "cPanel" elsewhere (an attacker could forge that word
//     anywhere in an INI file but cannot forge the specific header
//     position without cPanel regenerating the file);
//   - return false for an empty file and for nil/empty input.
// -----------------------------------------------------------------------------

func TestIsCpanelManagedUserIni_RealCpanelHeader(t *testing.T) {
	// Captured verbatim from /home/hospitalitycult/public_html/research_doc/.user.ini
	// on cluster6 during the 2026-04-16 scan cycle.
	data := []byte(`; cPanel-generated php ini directives, do not edit
; Manual editing of this file may result in unexpected behavior.
; To make changes to this file, use the cPanel MultiPHP INI Editor (Home >> Software >> MultiPHP INI Editor)
; For more information, read our documentation (https://go.cpanel.net/EA4ModifyINI)

[PHP]
display_errors = On
max_execution_time = 0
max_input_time = 60
`)
	if !isCpanelManagedUserIni(data) {
		t.Fatalf("real cPanel-generated .user.ini header must classify as managed")
	}
}

func TestIsCpanelManagedUserIni_MissingHeaderHandEdited(t *testing.T) {
	// Site owner hand-edited a .user.ini (or an attacker dropped one).
	// No cPanel header — must classify as NOT managed, preserving the
	// original finding severity.
	data := []byte(`max_execution_time = 0
display_errors = On
auto_prepend_file = /tmp/backdoor.php
`)
	if isCpanelManagedUserIni(data) {
		t.Fatalf("hand-edited .user.ini without cPanel header must not classify as managed")
	}
}

func TestIsCpanelManagedUserIni_ForgedCpanelMentionFarFromTop(t *testing.T) {
	// An attacker could write "cPanel" into the INI body to try to
	// evade detection. Only the specific header at the TOP of the file
	// indicates genuine cPanel management. A "cPanel" string buried
	// far below does not.
	data := []byte(`max_execution_time = 0
auto_prepend_file = /tmp/backdoor.php
; cPanel-generated php ini directives (forged comment, not a real header)
`)
	if isCpanelManagedUserIni(data) {
		t.Fatalf("forged cPanel mention buried in file body must not classify as managed")
	}
}

func TestIsCpanelManagedUserIni_EmptyAndNilInput(t *testing.T) {
	if isCpanelManagedUserIni(nil) {
		t.Errorf("nil input must not classify as managed")
	}
	if isCpanelManagedUserIni([]byte{}) {
		t.Errorf("empty input must not classify as managed")
	}
	if isCpanelManagedUserIni([]byte("\n\n\n")) {
		t.Errorf("whitespace-only input must not classify as managed")
	}
}

func TestIsCpanelManagedUserIni_LeadingBlankLinesToleratedModestly(t *testing.T) {
	// cPanel never prepends blank lines to the header, but a careful
	// admin might have run `echo > .user.ini` and pasted content back.
	// The signature is still expected to appear within the first few
	// lines; a small amount of leading whitespace should not break
	// detection. We do NOT want unbounded tolerance (a file with 50
	// blank lines then "cPanel-generated..." should be suspicious).
	data := []byte("\n\n; cPanel-generated php ini directives, do not edit\n[PHP]\ndisplay_errors = Off\n")
	if !isCpanelManagedUserIni(data) {
		t.Fatalf("signature within first few lines (after modest leading blanks) must classify as managed")
	}
}

func TestIsCpanelManagedUserIni_SignatureDeepInFileIsNotManaged(t *testing.T) {
	// A header that only appears after many lines of non-comment
	// content cannot be a cPanel-generated header; cPanel always
	// writes it at the top. Classify as NOT managed.
	buf := strings.Repeat("; some unrelated comment line\n", 50) +
		"; cPanel-generated php ini directives, do not edit\n" +
		"[PHP]\ndisplay_errors = Off\n"
	if isCpanelManagedUserIni([]byte(buf)) {
		t.Fatalf("signature appearing deep in the file must not classify as managed")
	}
}

func TestIsCpanelManagedUserIni_CaseSensitivityMatchesExact(t *testing.T) {
	// cPanel writes the capitalization exactly as "cPanel". A file
	// with "CPANEL-generated" or "cpanel-generated" is NOT cPanel-
	// generated — the writer is someone else masquerading. We match
	// exact capitalization to avoid accepting such forgeries.
	data := []byte("; CPANEL-generated php ini directives, do not edit\n[PHP]\n")
	if isCpanelManagedUserIni(data) {
		t.Fatalf("alternate-capitalization signature must not classify as managed")
	}
}

func TestIsCpanelManagedUserIni_ManyLeadingBlankLinesRejected(t *testing.T) {
	// Defence against header forgery: an attacker prepends a large run
	// of blank lines and then the cPanel header string. The intent of
	// the "first non-blank line must carry the signature" rule is that
	// the signature occupies the top of the file, not that it merely
	// appears somewhere after arbitrary whitespace. Without a cap on
	// leading blanks an attacker can bury their own content above the
	// cPanel header and still get the file classified as managed
	// (suppressing severity on their injected values below).
	data := []byte(strings.Repeat("\n", 50) + "; cPanel-generated php ini directives, do not edit\n[PHP]\ndisplay_errors = On\n")
	if isCpanelManagedUserIni(data) {
		t.Fatalf("signature after a large run of leading blanks must not classify as managed")
	}
}

func TestIsCpanelManagedUserIni_WindowsLineEndings(t *testing.T) {
	// CRLF line endings — some admins transfer files via FTP in text
	// mode and accumulate CRLFs. Must still classify correctly.
	data := []byte("; cPanel-generated php ini directives, do not edit\r\n[PHP]\r\ndisplay_errors = Off\r\n")
	if !isCpanelManagedUserIni(data) {
		t.Fatalf("CRLF-terminated cPanel header must classify as managed")
	}
}
