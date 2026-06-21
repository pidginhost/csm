package checks

import (
	"fmt"

	"github.com/pidginhost/csm/internal/alert"
)

// classifyUploadPHP decides severity, check name, and message for a fresh PHP
// file under wp-content/uploads using its CONTENT, never its path or name.
// Uploads should hold media, not PHP, so any new PHP is at least a visibility
// signal; the body decides whether it is an attack.
//
// A negative severity means "suppress" (a content-verified inert stub). It
// mirrors classifySensitiveDirPHP so the two anomalous-PHP-location detectors
// behave identically. Path/name allowlists are intentionally absent: skipping
// a file because it sits under /cache/ or is named index.php is exactly how an
// attacker hides a webshell in a "safe" location.
//
// Unreadable or zero-byte bodies fail closed at High: an attacker who races
// the scanner with `rm` or chmod 000 must not earn a demote. A content-clean
// real-code file surfaces as a non-actionable Warning under a check name that
// is intentionally absent from the correlation and auto-response maps -- a
// clean file is visibility, not an attack.
func classifyUploadPHP(path string) (alert.Severity, string, string) {
	sev, check, message, _ := classifyUploadPHPWithFingerprint(path)
	return sev, check, message
}

func classifyUploadPHPWithFingerprint(path string) (alert.Severity, string, string, string) {
	r, contentSHA256 := analyzePHPContentWithFingerprint(path)
	if r.severity >= 0 {
		return r.severity, r.check, fmt.Sprintf("%s: %s", r.message, path), contentSHA256
	}
	if !r.readOK {
		return alert.High, "new_php_in_uploads", fmt.Sprintf("New unreadable PHP file in uploads: %s", path), ""
	}
	if r.empty {
		return alert.High, "new_php_in_uploads", fmt.Sprintf("New empty PHP file in uploads: %s", path), ""
	}
	if IsBenignPHPStub(path) {
		return -1, "", "", ""
	}
	return alert.Warning, "new_php_in_uploads_clean", fmt.Sprintf("New PHP file in uploads (content clean): %s", path), ""
}
