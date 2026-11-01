package hostfacts

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/antispam"
)

// Replaced lists, in name order, the operator files the worker backed up in
// dir before replacing them. Only regular files with a backup name count:
// entries are judged by their own type, so a link is never followed. A
// missing dir means nothing was replaced.
func Replaced(dir string) ([]antispam.Replacement, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []antispam.Replacement
	for _, e := range entries {
		if target, ok := antispam.ParseBackupName(e.Name()); ok && e.Type().IsRegular() {
			out = append(out, antispam.Replacement{Path: target, Backup: filepath.Join(dir, e.Name())})
		}
	}
	return out, nil
}
