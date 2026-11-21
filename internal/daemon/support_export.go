package daemon

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/config"
)

// A configured key can have another name inside the state or rule tree.
// Compare the open file's identity as well as its configured path.
func supportExportFileFilter(cfg *config.Config) (func(string, os.FileInfo) bool, error) {
	paths := make(map[string]bool)
	var files []os.FileInfo
	for _, path := range cfg.SupportBundleKeyFiles() {
		if path == "" {
			continue
		}
		paths[filepath.Clean(path)] = true
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		files = append(files, info)
	}
	return func(path string, info os.FileInfo) bool {
		if paths[path] {
			return false
		}
		for _, private := range files {
			if os.SameFile(info, private) {
				return false
			}
		}
		return true
	}, nil
}
