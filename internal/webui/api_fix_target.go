package webui

import (
	"fmt"
	"path/filepath"

	"github.com/pidginhost/csm/internal/alert"
)

// fixTargetFromStore pins a fix request to the stored finding it names. The
// returned snapshot is the evidence a successful fix may resolve.
// Only when the finding is no longer in the latest set does the client input
// stand on its own, bounded by the remediation roots as before.
func (s *Server) fixTargetFromStore(key, check, message, details, filePath string) (string, string, string, alert.Finding, error) {
	latest := s.store.LatestFindings()
	if key != "" {
		for _, f := range latest {
			if f.Key() != key {
				continue
			}
			if f.Check != check {
				return "", "", "", alert.Finding{}, fmt.Errorf("check does not match the stored finding")
			}
			return storedFixTarget(f, filePath)
		}
	}

	var matched alert.Finding
	found := false
	for _, f := range latest {
		if f.Check != check || f.Message != message {
			continue
		}
		if found {
			return "", "", "", alert.Finding{}, fmt.Errorf("finding key is required for an ambiguous fix target")
		}
		matched = f
		found = true
	}
	if !found {
		return message, details, filePath, alert.Finding{}, nil
	}
	return storedFixTarget(matched, filePath)
}

func storedFixTarget(f alert.Finding, requestedPath string) (string, string, string, alert.Finding, error) {
	// Older findings have no FilePath. Their stored message remains the
	// authority; a caller-supplied path must not replace it.
	if f.FilePath != "" && requestedPath != "" && filepath.Clean(requestedPath) != filepath.Clean(f.FilePath) {
		return "", "", "", alert.Finding{}, fmt.Errorf("file_path does not match the stored finding")
	}
	return f.Message, f.Details, f.FilePath, f, nil
}
