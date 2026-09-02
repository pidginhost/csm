package webui

import (
	"fmt"
	"path/filepath"
)

// fixTargetFromStore pins a fix request to the stored finding it names: the
// remediation runs against the stored message, details and path, and a
// client path that differs from the stored one is refused. Only when the
// finding is no longer in the latest set does the client input stand on its
// own, bounded by the remediation roots as before.
func (s *Server) fixTargetFromStore(key, check, message, details, filePath string) (string, string, string, error) {
	f, ok := s.latestFindingForVerify(key, check, message)
	if !ok {
		return message, details, filePath, nil
	}
	if filePath != "" && filepath.Clean(filePath) != filepath.Clean(f.FilePath) {
		return "", "", "", fmt.Errorf("file_path does not match the stored finding")
	}
	return f.Message, f.Details, f.FilePath, nil
}
