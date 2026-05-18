package checks

import (
	"github.com/pidginhost/csm/internal/alert"
)

// scorePHPUploadSeverity decides the alert severity for a fresh PHP file
// dropped under wp-content/uploads. Default is High because writable PHP
// in uploads is real attack surface; the detector exists to surface every
// drop. We demote to Warning only when analyzePHPContent reads the body
// and produces zero indicators, which means none of the obfuscation,
// remote-payload, shell-execution, or hex-concat heuristics matched. Any
// read error (missing file, zero bytes, permission denial) fails closed
// at High -- an attacker who races the scanner with `rm` or chmod 000
// must not get a free demote.
//
// Yara coverage is intentionally not invoked here. The deep tier's
// CheckPHPContent runs on its own schedule across the same uploads tree
// and will emit obfuscated_php / suspicious_php_content independently,
// so a truly malicious file produces a separate High/Critical finding
// even after this demote.
func scorePHPUploadSeverity(path string) alert.Severity {
	r := analyzePHPContent(path)
	if r.severity >= alert.High {
		return alert.High
	}
	if r.readOK {
		return alert.Warning
	}
	return alert.High
}
