package checks

import (
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
// Unverifiable input fails closed: no boot time, no stat, or an unparsable
// field all report false, and the caller does not kill.
//
// (internal/daemon carries its own copy of this parse for the af_alg reaction:
// it reads procfs directly rather than through this package's filesystem seam,
// and sharing one implementation would mean mixing two abstractions.)
func processStartedBefore(pid string, t time.Time) bool {
	if pid == "" || t.IsZero() {
		return false
	}
	boot, ok := procBootTime()
	if !ok {
		return false
	}
	ticks, ok := procStartTicks(pid)
	if !ok {
		return false
	}
	started := float64(boot) + ticks/procClockTicks
	// A second of slack absorbs the clock-tick resolution of starttime.
	return started <= float64(t.Unix())+1
}

func procBootTime() (int64, bool) {
	data, err := osFS.ReadFile("/proc/stat")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		rest, found := strings.CutPrefix(line, "btime ")
		if !found {
			continue
		}
		boot, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
		if err != nil {
			return 0, false
		}
		return boot, true
	}
	return 0, false
}

func procStartTicks(pid string) (float64, bool) {
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
	ticks, err := strconv.ParseFloat(fields[19], 64)
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
	if pid == "" || path == "" {
		return false
	}
	clean := filepath.Clean(path)
	if exe := getProcessExe(pid); exe != "" {
		if filepath.Clean(strings.TrimSuffix(exe, " (deleted)")) == clean {
			return true
		}
	}
	fdDir := filepath.Join("/proc", pid, "fd")
	entries, err := osFS.ReadDir(fdDir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		target, err := osFS.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if filepath.Clean(strings.TrimSuffix(target, " (deleted)")) == clean {
			return true
		}
	}
	return false
}
