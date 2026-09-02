package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// quarantineSafeNameMax keeps the generated name, plus the timestamp prefix
// callers add, under the 255-byte filename limit.
const quarantineSafeNameMax = 180

// quarantineSafeName turns a source path into one flat quarantine filename.
// Short paths keep the familiar slash-to-underscore form. A path that would
// exceed the filename limit is shortened to a hash of the whole path plus
// its tail, so the file name survives, two long paths cannot collide, and
// the move no longer fails with ENAMETOOLONG (which left the malware in
// place while the finding reported a quarantine attempt).
func quarantineSafeName(path string) string {
	flat := strings.ReplaceAll(path, "/", "_")
	if len(flat) <= quarantineSafeNameMax {
		return flat
	}
	sum := sha256.Sum256([]byte(path))
	prefix := hex.EncodeToString(sum[:6])
	tail := flat[len(flat)-(quarantineSafeNameMax-len(prefix)-1):]
	return prefix + "_" + tail
}
