package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// A queued finding can outlive its removal record or the bytes it reported.
// Only a current removal and a stable read authorize repeating the response.
func restoredFileResponseInfo(path, key string, expected os.FileInfo) (RemovedFile, os.FileInfo) {
	removed, ok := RemovedFileAt(path)
	if !ok || key != removed.RestoreKey() {
		return RemovedFile{}, nil
	}
	target, err := openCleanTarget(path)
	if err != nil {
		return RemovedFile{}, nil
	}
	defer target.Close()
	if target.Info.Size() != removed.Size || !SameFileVersion(expected, target.Info) {
		return RemovedFile{}, nil
	}
	if contentErr := requireRemovedContent(target.File, removed); contentErr != nil {
		return RemovedFile{}, nil
	}
	after, err := target.File.Stat()
	if err != nil || !SameFileVersion(target.Info, after) {
		return RemovedFile{}, nil
	}
	return removed, after
}

func requireRemovedContent(file *os.File, removed RemovedFile) error {
	current, ok := RemovedFileAt(removed.Path)
	if !ok || current != removed {
		return errors.New("removal evidence changed")
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(file, 0, removed.Size)); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != removed.SHA256 {
		return errors.New("content differs from the removed bytes")
	}
	return nil
}

func quarantineRestoredTarget(path, qPath string, info os.FileInfo, metadata QuarantineMeta, removed RemovedFile) error {
	return quarantineTargetWith(path, qPath, info, metadata, func(path, qPath string, info os.FileInfo, data []byte) error {
		// Validate the whole digest under the existing exclusive lease. A
		// same-tick rewrite must not substitute content after the first hash.
		return quarantineFileTOCTOUSafeMode(path, qPath, info, data, true, -1, func(file *os.File) error {
			return requireRemovedContent(file, removed)
		})
	})
}
