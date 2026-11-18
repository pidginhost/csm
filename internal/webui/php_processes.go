package webui

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/platform"
)

// scanPHPProcesses reads executable names from procfs. Command lines can be
// large and can mention PHP in arguments to an unrelated executable.
func scanPHPProcesses(procRoot, shieldPath string) (running, shielded bool) {
	proc, err := os.Open(procRoot) // #nosec G304 -- kernel procfs directory in production.
	if err != nil {
		return false, false
	}
	defer proc.Close()
	for {
		entries, readErr := proc.ReadDir(128)
		for _, entry := range entries {
			if !entry.IsDir() || strings.Trim(entry.Name(), "0123456789") != "" {
				continue
			}
			pid := filepath.Join(procRoot, entry.Name())
			exe, err := os.Readlink(filepath.Join(pid, "exe"))
			if err != nil || !platform.IsPHPServerBinary(filepath.Base(strings.TrimSuffix(exe, " (deleted)"))) {
				continue
			}
			running = true
			if processHasShield(pid, shieldPath) {
				return true, true
			}
		}
		if readErr != nil {
			return running, false
		}
	}
}

func processHasShield(pid, shieldPath string) bool {
	// Follow the kernel's root link once. Resolve every container-controlled
	// component relative to that directory, even if a symlink changes.
	root, err := os.OpenRoot(filepath.Join(pid, "root"))
	if err != nil {
		return false
	}
	defer func() { _ = root.Close() }()
	fi, err := root.Lstat(strings.TrimPrefix(shieldPath, "/"))
	return err == nil && fi.Mode().IsRegular()
}
