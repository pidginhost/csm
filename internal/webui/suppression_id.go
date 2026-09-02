package webui

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// newSuppressionID returns a fresh opaque rule ID. Shared by the UI add path
// and the import path so an imported rule without an ID can be deleted like
// any other.
func newSuppressionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "sup-" + hex.EncodeToString([]byte(time.Now().UTC().Format("20060102150405.000000000")))
	}
	return hex.EncodeToString(b)
}
