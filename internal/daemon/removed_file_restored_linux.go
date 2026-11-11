//go:build linux

package daemon

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// checkRemovedFileRestored reports a write that puts back, byte for byte, the
// content CSM quarantined or cleaned at the same path. A process doing that is
// undoing a response, typically a loop that rewrites a webshell whenever it
// goes missing, so the report does not depend on what the content detectors
// make of the bytes.
func (fm *FileMonitor) checkRemovedFileRestored(event fileEvent, procInfo string) bool {
	removed, ok := removedFileAt(event.path)
	if !ok || int(event.pid) == os.Getpid() {
		return false
	}
	var st unix.Stat_t
	if err := unix.Fstat(event.fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size != removed.Size {
		return false
	}
	if hashEventFD(event.fd, nil, st.Size) != removed.SHA256 {
		return false
	}
	fm.sendFileFinding(removedFileRestoredFinding(event.path, removed, procInfo, event.pid))
	return true
}

func removedFileRestoredFinding(path string, removed checks.RemovedFile, procInfo string, pid int32) alert.Finding {
	return alert.Finding{
		Severity: alert.Critical,
		Check:    checks.RemovedFileRestoredCheck,
		Message:  fmt.Sprintf("File CSM removed was written back: %s", path),
		Details: fmt.Sprintf("CSM %s this content at %s; a process wrote the same bytes back.\nSHA-256: %s",
			removedActionPast(removed.Action), removed.At.UTC().Format(time.RFC3339), removed.SHA256),
		FilePath:    path,
		ProcessInfo: procInfo,
		PID:         int(pid),
		// One report per removal: a file written back after CSM removed it
		// again is a new event, not a repeat of the first. The removal time,
		// unlike its sequence, stays unique across daemon restarts.
		DedupKey: fmt.Sprintf("%s:removed-%d", path, removed.At.UnixNano()),
	}
}

func removedActionPast(action string) string {
	if action == "clean" {
		return "cleaned"
	}
	return "quarantined"
}
