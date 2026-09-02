package daemon

import (
	"os"
	"path/filepath"
	"sort"
)

// eximSplitSpoolDirName reports whether name is one of the hash
// subdirectories Exim creates under input/ when split_spool_directory is
// on: a single character from [0-9A-Za-z], taken from the message ID.
func eximSplitSpoolDirName(name string) bool {
	if len(name) != 1 {
		return false
	}
	c := name[0]
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// spoolMarkTargets returns the directories a spool watcher has to mark to
// see every message file under root: the root itself (flat spool) and every
// split-spool hash subdirectory present right now, sorted. A missing root
// yields nil. Exim creates hash directories lazily, so callers re-run this
// periodically and mark whatever is new.
func spoolMarkTargets(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	targets := []string{root}
	for _, e := range entries {
		if e.IsDir() && eximSplitSpoolDirName(e.Name()) {
			targets = append(targets, filepath.Join(root, e.Name()))
		}
	}
	sort.Strings(targets[1:])
	return targets
}
