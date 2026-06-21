package checks

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/pidginhost/csm/internal/signatures"
	"github.com/pidginhost/csm/internal/yara"
)

// ContentLogicVersion identifies the current shape of the PHP content-analysis
// heuristic set (analyzePHPContent and its helpers). BUMP IT in the same commit
// as any change to those heuristics, so findings produced by the previous logic
// are re-verified and cleared by the daemon sweep. See
// docs/superpowers/specs/2026-06-20-stale-content-finding-reverification-design.md.
const ContentLogicVersion = 1

// contentReverifiableChecks are content findings whose condition can be
// re-evaluated by re-running the classifier that produced them on the file's
// current bytes. Unlike presenceVerifiableChecks, a still-present file may be
// resolved -- but ONLY when its bytes are byte-for-byte identical to detection
// time (ContentSHA256 match) and the current classifier no longer flags them.
// A file modified since detection is never auto-cleared (it could be a partial
// clean or an evasion edit), preserving the guarantee behind the presence-only
// design.
var contentReverifiableChecks = []string{
	"suspicious_php_content",
	"obfuscated_php", "obfuscated_php_realtime",
	"php_dropper_realtime",
	"webshell", "webshell_realtime", "webshell_content_realtime",
	"new_webshell_file", "new_suspicious_php",
	"new_php_in_sensitive_dir", "new_php_in_uploads",
	"php_in_sensitive_dir_realtime", "php_in_uploads_realtime",
	"signature_match_realtime", "yara_match_realtime",
}

var contentReverifiableSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(contentReverifiableChecks))
	for _, c := range contentReverifiableChecks {
		m[c] = struct{}{}
	}
	return m
}()

// IsContentReverifiable reports whether a check type is re-evaluated by
// re-running the content classifier (vs presence-only).
func IsContentReverifiable(check string) bool {
	_, ok := contentReverifiableSet[check]
	return ok
}

// ContentDetectionVersion returns a token identifying the full content-detection
// logic in effect: the heuristic version, the loaded signature-set version, and
// the loaded YARA rule count. The re-verifier always re-runs the real
// classifier, so this token only gates the daemon sweep and enriches audit
// detail; its precision is not security-critical.
func ContentDetectionVersion() string {
	sigVer := 0
	if s := signatures.Global(); s != nil {
		sigVer = s.Version()
	}
	yaraRules := 0
	if y := yara.Active(); y != nil {
		yaraRules = y.RuleCount()
	}
	return fmt.Sprintf("php=%d;sig=%d;yara=%d", ContentLogicVersion, sigVer, yaraRules)
}

// contentFingerprintMaxBytes caps the file size hashed for a finding's
// fingerprint. Larger files get an empty fingerprint, so the re-verifier treats
// them as un-fingerprinted (never auto-cleared while present).
const contentFingerprintMaxBytes = 16 << 20 // 16 MiB

// FileContentSHA256 returns the hex SHA-256 of the whole file, or "" if the
// file cannot be read, is not a regular file, or exceeds the size cap.
func FileContentSHA256(path string) string {
	info, err := osFS.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > contentFingerprintMaxBytes {
		return ""
	}
	f, err := osFS.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
