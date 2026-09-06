package checks

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"time"
)

// quarantineSafeNameMax keeps the generated name, plus the timestamp prefix
// callers add, under the 255-byte filename limit.
const quarantineSafeNameMax = 180

func newQuarantinePath(dir, original string) string {
	// Repeated cleanups can occur within one second. Independent names keep
	// a new recovery point from replacing the only copy of an earlier state.
	return filepath.Join(dir, time.Now().UTC().Format("20060102-150405")+"_"+rand.Text()+"_"+quarantineSafeName(original))
}

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
