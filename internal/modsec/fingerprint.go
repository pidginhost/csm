package modsec

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// RuleTreeFingerprint summarises the rule files BuildRegistry would parse:
// every .conf file under dirs, with its size and modification time. Two calls
// that return the same fingerprint describe the same rule tree, so the caller
// can skip a rebuild that would parse hundreds of files to reach the registry
// it already holds.
//
// present is false when none of the dirs exist. That is the signal that the
// resolved directories no longer describe this host (a web server swapped out,
// a vendor pack removed) and detection has to run again; it is not the same as
// a rule tree that exists and happens to be empty.
//
// The fingerprint covers file identity and timestamps rather than content:
// reading every rule file to hash it would cost what the parse costs. An
// in-place rewrite that preserves both size and mtime is indistinguishable,
// which is why this gates the periodic refresh only. Operator edits move the
// mtime, and the daemon rebuilds on SIGHUP regardless.
func RuleTreeFingerprint(dirs []string) (string, bool) {
	digest := sha256.New()
	present := false
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			present = true
		}
		// WalkDir yields lexical order, so the digest is stable across calls.
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if errors.Is(walkErr, fs.ErrNotExist) {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".conf") {
				return nil
			}
			// An unreadable entry still has to change the fingerprint, or a
			// file that becomes readable later never triggers a rebuild.
			if info, infoErr := d.Info(); infoErr == nil {
				fmt.Fprintf(digest, "%s\x00%d\x00%d\n", path, info.Size(), info.ModTime().UnixNano())
			} else {
				fmt.Fprintf(digest, "%s\x00unreadable\n", path)
			}
			return nil
		})
	}
	return hex.EncodeToString(digest.Sum(nil)), present
}
