package processctx

import (
	"errors"
	"io/fs"
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
// while it runs still matches. The oldest process must have serverTitle as
// its rewritten argv[0]; connection workers cannot establish a server's
// configuration. Incomplete inspection of a candidate fails closed.
func EarliestRootStart(procRoot string, names []string, serverTitle string) (pid int, started time.Time, ok bool) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, time.Time{}, false
	}
	reader := NewProcReader(procRoot, time.Second)
	for _, entry := range entries {
		n, err := strconv.Atoi(entry.Name())
		if err != nil || n <= 0 {
			continue
		}
		// Most processes are something else; skip them before reading more.
		exe, err := os.Readlink(filepath.Join(procRoot, entry.Name(), "exe"))
		if errors.Is(err, fs.ErrNotExist) {
			// Exited processes and kernel threads have no executable link.
			continue
		}
		if err != nil {
			return 0, time.Time{}, false
		}
		if !executableNamed(exe, names) {
			continue
		}
		before, known := reader.ReadStartedAt(n)
		e, err := reader.Read(n)
		if e.UIDKnown && e.UID != 0 {
			continue
		}
		if err != nil || !executableNamed(e.Exe, names) || !e.UIDKnown ||
			!known || !before.Equal(e.StartedAt) || len(e.Cmdline) == 0 {
			return 0, time.Time{}, false
		}
		// Forked children can share the listener's start tick. Prefer the
		// listener at that same lower bound, regardless of directory order.
		isServer := len(e.Cmdline) == 1 && strings.TrimSpace(e.Cmdline[0]) == serverTitle
		if !ok || e.StartedAt.Before(started) || e.StartedAt.Equal(started) && isServer {
			pid, started, ok = n, e.StartedAt, true
		}
	}
	if !ok {
		return 0, time.Time{}, false
	}
	// Recheck the selected server after the scan: it may have exited, exec'd,
	// or dropped privileges while other candidates were inspected.
	at, valid := reader.ReadRootServerStart(pid, names, serverTitle)
	if !valid || !at.Equal(started) {
		return 0, time.Time{}, false
	}
	return pid, started, true
}

func executableNamed(exe string, names []string) bool {
	return slices.Contains(names, filepath.Base(strings.TrimSuffix(exe, " (deleted)")))
}

// ReadRootServerStart validates both identity and role on a remembered PID.
// A start time alone survives exec and privilege changes.
func (r *ProcReader) ReadRootServerStart(pid int, names []string, serverTitle string) (time.Time, bool) {
	before, ok := r.ReadStartedAt(pid)
	if !ok {
		return time.Time{}, false
	}
	e, err := r.Read(pid)
	if err != nil || !e.UIDKnown || e.UID != 0 || !executableNamed(e.Exe, names) ||
		!before.Equal(e.StartedAt) || len(e.Cmdline) != 1 || strings.TrimSpace(e.Cmdline[0]) != serverTitle {
		return time.Time{}, false
	}
	return e.StartedAt, true
}
