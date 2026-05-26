//go:build !linux

package checks

import (
	"fmt"
	"os"
)

// quarantineFileTOCTOUSafe stub for non-Linux build targets. CSM's
// quarantine path only runs on Linux production hosts; this keeps the
// Go module building on macOS and other dev platforms without pulling
// in the Linux-specific /proc/self/fd hardlink trick.
func quarantineFileTOCTOUSafe(path, qPath string, originalInfo os.FileInfo) error {
	if originalInfo == nil {
		return fmt.Errorf("quarantine: missing original stat")
	}
	if err := os.Rename(path, qPath); err != nil {
		return fmt.Errorf("quarantine: rename %s -> %s: %w", path, qPath, err)
	}
	return nil
}
