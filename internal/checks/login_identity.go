package checks

import (
	"crypto/sha256"
	"fmt"
)

// loginRecordKey retains session identity even when the syslog prefix is long
// enough to push the PID or client port past the display-details truncation.
func loginRecordKey(line string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(line)))
}
