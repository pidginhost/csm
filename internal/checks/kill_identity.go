package checks

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// procClockTicks is USER_HZ, 100 on the platforms CSM runs on.
const procClockTicks = 100.0

// processStartedBefore reports whether pid's process began before t.
//
// A PID is recycled freely on a busy host, and a finding can be acted on long
// after it was raised -- immediately by auto-response, or whenever an operator
// clicks Fix. Killing by number alone therefore risks destroying a process that
// merely inherited the PID. A process that started after the finding cannot be
// the one the finding describes.
//
// Unverifiable input fails closed: no uptime, no stat, or an unparsable
// field all report false, and the caller does not kill.
//
// (internal/daemon carries its own copy of this parse for the af_alg reaction:
// it reads procfs directly rather than through this package's filesystem seam,
// and sharing one implementation would mean mixing two abstractions.)
func processStartedBefore(pid string, t time.Time) bool {
	pidInt, ok := parseProcessPID(pid)
	if !ok || t.IsZero() {
		return false
	}
	ticks, ok := procStartTicks(strconv.Itoa(pidInt))
	if !ok {
		return false
	}
	uptime, ok := procUptime()
	if !ok {
		return false
	}
	// Read wall time after uptime so elapsed is conservatively rounded up. A
	// process close enough to the boundary to be ambiguous is not killed.
	elapsed := time.Since(t).Seconds()
	if elapsed < 0 {
		return false
	}
	eventUptime := uptime - elapsed
	return eventUptime >= 0 && float64(ticks)/procClockTicks <= eventUptime
}

func parseProcessPID(pid string) (int, bool) {
	n, err := strconv.Atoi(pid)
	return n, err == nil && n > 1
}

func procUptime() (float64, bool) {
	data, err := osFS.ReadFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, false
	}
	uptime, err := strconv.ParseFloat(fields[0], 64)
	return uptime, err == nil && !math.IsNaN(uptime) && !math.IsInf(uptime, 0) && uptime >= 0
}

func procStartTicks(pid string) (uint64, bool) {
	data, err := osFS.ReadFile(filepath.Join("/proc", pid, "stat"))
	if err != nil {
		return 0, false
	}
	// The comm field is parenthesised and may contain spaces, so fields are
	// counted from after its closing parenthesis.
	closing := strings.LastIndex(string(data), ")")
	if closing < 0 {
		return 0, false
	}
	fields := strings.Fields(string(data)[closing+1:])
	// starttime is field 22 overall, index 19 once pid and comm are behind us.
	if len(fields) < 20 {
		return 0, false
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return ticks, true
}

// processUsesFile reports whether pid still references path, as its executable
// or through an open descriptor. The kill in fixKillAndQuarantine exists to
// release the file being quarantined; a process that no longer references that
// file is not the process the finding meant, so it is not killed.
func processUsesFile(pid, path string) bool {
	pidInt, ok := parseProcessPID(pid)
	if !ok || path == "" {
		return false
	}
	target, err := osFS.Lstat(path)
	if err != nil || target.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return processUsesFileIdentity(pidInt, target)
}

func processUsesFileIdentity(pid int, target os.FileInfo) bool {
	if pid <= 1 || target == nil || target.Mode()&os.ModeSymlink != 0 {
		return false
	}
	procDir := filepath.Join("/proc", strconv.Itoa(pid))
	if info, statErr := osFS.Stat(filepath.Join(procDir, "exe")); statErr == nil && sameObject(info, target) {
		return true
	}
	fdDir := filepath.Join(procDir, "fd")
	entries, err := osFS.ReadDir(fdDir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		info, err := osFS.Stat(filepath.Join(fdDir, entry.Name()))
		if err == nil && sameObject(info, target) {
			return true
		}
	}
	return false
}

// sameObject reports whether two stats describe the same file, requiring the
// content shape to agree as well as device and inode. A deleted inode is handed
// straight back to the next file created in the same directory, so dev+ino
// alone would call a descriptor for the removed file the same object as its
// replacement -- the same inode-reuse hole the quarantine move already guards
// against.
func sameObject(a, b os.FileInfo) bool {
	return sameFileIdentity(a, b) && sameContentShape(a, b)
}
