package webui

import (
	"fmt"
	"path/filepath"

	"github.com/pidginhost/csm/internal/alert"
)

// fixTargetFromStore pins a fix request to the stored finding it names. The
// returned key is also the key that must be dismissed after a successful fix.
// Only when the finding is no longer in the latest set does the client input
// stand on its own, bounded by the remediation roots as before.
func (s *Server) fixTargetFromStore(key, check, message, details, filePath string) (string, string, string, string, error) {
	latest := s.store.LatestFindings()
	if key != "" {
		for _, f := range latest {
			if f.Key() != key {
				continue
			}
			if f.Check != check {
				return "", "", "", "", fmt.Errorf("check does not match the stored finding")
			}
			return storedFixTarget(f.Message, f.Details, f.FilePath, f.Key(), filePath)
		}
	}

	var matched alert.Finding
	found := false
	for _, f := range latest {
		if f.Check != check || f.Message != message {
			continue
		}
		if found {
			return "", "", "", "", fmt.Errorf("finding key is required for an ambiguous fix target")
		}
		matched = f
		found = true
	}
	if !found {
		if key != "" {
			return message, details, filePath, key, nil
		}
		return message, details, filePath, check + ":" + message, nil
	}
	return storedFixTarget(matched.Message, matched.Details, matched.FilePath, matched.Key(), filePath)
}

func storedFixTarget(message, details, storedPath, key, requestedPath string) (string, string, string, string, error) {
	// Older findings may not have FilePath populated. In that case the stored
	// message remains the authority and the remediation extracts its path from
	// there; a caller-supplied path must not replace it.
	if storedPath != "" && requestedPath != "" && filepath.Clean(requestedPath) != filepath.Clean(storedPath) {
		return "", "", "", "", fmt.Errorf("file_path does not match the stored finding")
	}
	return message, details, storedPath, key, nil
}
