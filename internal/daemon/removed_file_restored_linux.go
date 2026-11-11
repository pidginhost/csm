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
	before := scannedIdentity(event.fd)
	// A removal too large to hash and a failed read both leave no digest.
	if digest := hashEventFD(event.fd, nil, st.Size); digest == "" || digest != removed.SHA256 {
		return false
	}
	after := scannedIdentity(event.fd)
	current, err := os.Lstat(event.path)
	if err != nil || !checks.SameFileVersion(before, after) || !checks.SameFileVersion(after, current) {
		return false
	}
	// An operator restore or another response may have invalidated the
	// ledger entry while this descriptor was being hashed.
	latest, ok := removedFileAt(event.path)
	if !ok || latest != removed {
		return false
	}
	f := removedFileRestoredFinding(event.path, removed, procInfo, event.pid)
	f.WriterChain, f.WriterObservedAt = event.writerChain, event.at
	fm.sendFileFinding(f)
	return true
}

// Capture before analyzer queuing: the writer may exit during content analysis,
// but its still-running parents must remain eligible for the response.
func captureRestoreWriterChain(event *fileEvent) {
	if event.pid <= 1 || int(event.pid) == os.Getpid() {
		return
	}
	if _, ok := removedFileAt(event.path); ok {
		event.writerChain = restoreWriterChain(int(event.pid), event.at)
	}
}

// restoreWriterChain lets tests observe what the detector captures.
var restoreWriterChain = checks.RestoreWriterChain

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
		DedupKey: removed.RestoreKey(),
	}
}

func removedActionPast(action string) string {
	if action == "clean" {
		return "cleaned"
	}
	return "quarantined"
}
