package signatures

import (
	"path/filepath"
	"runtime"
)

// repoConfigsDir resolves the checked-in configs directory from this file's
// own location so tests read the same rules the daemon ships.
func repoConfigsDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "configs")
}
