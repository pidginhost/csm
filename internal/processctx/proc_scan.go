package processctx

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// EarliestRootStart returns the root-owned process that started first among
// those running an executable named one of names, and when it started. A
// server keeps what it read when it started, so its oldest process decides
// whether a later configuration change applies. Other users' processes are
// ignored: anyone can run a copy of a server binary. An executable replaced
// while it runs still matches.
func EarliestRootStart(procRoot string, names []string) (pid int, started time.Time, ok bool) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, time.Time{}, false
	}
	named := func(exe string) bool {
		return slices.Contains(names, filepath.Base(strings.TrimSuffix(exe, " (deleted)")))
	}
	reader := NewProcReader(procRoot, time.Second)
	for _, entry := range entries {
		n, err := strconv.Atoi(entry.Name())
		if err != nil || n <= 0 {
			continue
		}
		// Most processes are something else; skip them before reading more.
		exe, err := os.Readlink(filepath.Join(procRoot, entry.Name(), "exe"))
		if err != nil || !named(exe) {
			continue
		}
		e, err := reader.Read(n)
		// The exe is read again with the rest: a reused pid is not the server.
		if err != nil || !named(e.Exe) || !e.UIDKnown || e.UID != 0 || e.StartedAt.IsZero() {
			continue
		}
		if !ok || e.StartedAt.Before(started) {
			pid, started, ok = n, e.StartedAt, true
		}
	}
	return pid, started, ok
}
