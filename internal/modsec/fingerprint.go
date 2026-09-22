package modsec

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// RuleTreeFingerprint summarises the rule files BuildRegistry would parse:
// their paths, contents and directory precedence. Content hashing catches
// vendor updates that preserve timestamps and changes behind .conf symlinks,
// while avoiding the rule parser's allocations and action extraction.
// An empty fingerprint means a read failed and must never skip a rebuild.
//
// present is false when none of the dirs exist. That is the signal that the
// resolved directories no longer describe this host (a web server swapped out,
// a vendor pack removed) and detection has to run again; it is not the same as
// a rule tree that exists and happens to be empty.
func RuleTreeFingerprint(dirs []string) (string, bool) {
	digest := sha256.New()
	present := false
	complete := true
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			present = true
		}
		fmt.Fprintf(digest, "dir:%q\n", dir)
		err := walkRuleFiles(dir, func(path string) error {
			fileDigest, err := readRuleFile(path, func(reader io.Reader) error {
				_, err := io.Copy(io.Discard, reader)
				return err
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(digest, "file:%q:%x\n", path, fileDigest)
			return nil
		})
		if err != nil {
			complete = false
		}
	}
	if !complete {
		return "", present
	}
	return hex.EncodeToString(digest.Sum(nil)), present
}

// Hash the same stream the consumer reads so a concurrent rewrite cannot
// associate parsed actions with a fingerprint of different file contents.
func readRuleFile(path string, consume func(io.Reader) error) ([]byte, error) {
	// #nosec G304 -- path comes from the operator's ModSec rule directories.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	readErr := consume(io.TeeReader(f, digest))
	if err := errors.Join(readErr, f.Close()); err != nil {
		return nil, err
	}
	return digest.Sum(nil), nil
}
