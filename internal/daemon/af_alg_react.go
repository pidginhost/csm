//go:build linux

package daemon

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// reactToAFAlgEvent applies opt-in live reactions when an AF_ALG socket
// open is caught by either the audit-log listener or the BPF LSM hook.
// Currently supports a single reaction: SIGKILL the offending process
// (gated by config.AutoResponse.CopyFailKillProcess).
//
// Reactions are intentionally narrow: a critical alert is always emitted
// by the listener itself (this function is for *additional* responses
// beyond alerting). Quarantining the offending exe is a future addition;
// keeping the surface minimal until the kill path has been observed in
// production.
//
// Refuses to act on PID 0/1 to avoid catastrophic mistakes if the parser
// ever returns something unexpected.
func reactToAFAlgEvent(cfg *config.Config, ev checks.AFAlgEvent) {
	if cfg == nil || !cfg.AutoResponse.CopyFailKillProcess {
		return
	}
	pid, ok, reason := afAlgKillTarget(ev)
	if !ok {
		csmlog.Warn("af_alg react: refusing to kill",
			"reason", reason,
			"pid", ev.PID, "exe", ev.Exe, "uid", ev.UID,
		)
		return
	}
	if err := unix.Kill(pid, unix.SIGKILL); err != nil {
		csmlog.Warn("af_alg react: kill failed",
			"pid", pid, "exe", ev.Exe, "uid", ev.UID,
			"err", err,
		)
		return
	}
	csmlog.Info("af_alg react: killed offending process",
		"pid", pid, "exe", ev.Exe, "uid", ev.UID, "comm", ev.Comm,
	)
}

// afAlgKillTarget reports whether ev still names the process it described, and
// may therefore be killed.
//
// The audit record can be a tick old by the time it is read. A PID is recycled
// freely on a busy host, so acting on the number alone means SIGKILLing a
// process that merely inherited it -- as root, on a production server. Three
// facts must agree before the kill: the executable behind the PID is the one
// the record named, the process is owned by the recorded user, and it started
// no later than the event. A process that began after the event cannot be the
// one the event describes.
//
// Anything unverifiable fails closed: an event with no executable, an
// unreadable procfs entry, or a process that has already exited.
func afAlgKillTarget(ev checks.AFAlgEvent) (int, bool, string) {
	pid, err := strconv.Atoi(ev.PID)
	if err != nil || pid <= 1 {
		return 0, false, "implausible pid"
	}
	if ev.Exe == "" || ev.Exe == "(null)" {
		return 0, false, "event carries no executable to verify"
	}

	exe, err := os.Readlink(fmt.Sprintf("%s/%d/exe", procRootDir, pid))
	if err != nil {
		return 0, false, "process is gone or its executable is unreadable"
	}
	// A deleted binary is reported as "<path> (deleted)".
	if exe != ev.Exe && strings.TrimSuffix(exe, " (deleted)") != ev.Exe {
		return 0, false, "pid now runs a different executable"
	}

	if ev.UID != "" {
		var st unix.Stat_t
		if err := unix.Stat(fmt.Sprintf("%s/%d", procRootDir, pid), &st); err != nil {
			return 0, false, "process ownership unreadable"
		}
		if strconv.FormatUint(uint64(st.Uid), 10) != ev.UID {
			return 0, false, "pid now belongs to a different user"
		}
	}

	started, ok := afAlgProcessStart(pid)
	eventAt, evErr := strconv.ParseFloat(ev.Timestamp, 64)
	if !ok || evErr != nil {
		return 0, false, "process start time could not be compared with the event"
	}
	// One second of slack absorbs the clock-tick resolution of starttime and
	// any rounding in the audit timestamp.
	if started > eventAt+1 {
		return 0, false, "pid was recycled after the event"
	}
	return pid, true, ""
}

// afAlgProcessStart returns the wall-clock start time of pid, in seconds since
// the epoch, from the boot time in /proc/stat plus the process's starttime.
func afAlgProcessStart(pid int) (float64, bool) {
	bootData, err := os.ReadFile(fmt.Sprintf("%s/stat", procRootDir))
	if err != nil {
		return 0, false
	}
	var boot float64
	for _, line := range strings.Split(string(bootData), "\n") {
		if rest, found := strings.CutPrefix(line, "btime "); found {
			boot, err = strconv.ParseFloat(strings.TrimSpace(rest), 64)
			if err != nil {
				return 0, false
			}
			break
		}
	}
	if boot == 0 {
		return 0, false
	}

	statData, err := os.ReadFile(fmt.Sprintf("%s/%d/stat", procRootDir, pid))
	if err != nil {
		return 0, false
	}
	// The comm field is parenthesised and may contain spaces, so fields are
	// counted from after the closing parenthesis.
	close := strings.LastIndex(string(statData), ")")
	if close < 0 {
		return 0, false
	}
	fields := strings.Fields(string(statData)[close+1:])
	// starttime is field 22 overall, which is index 19 after pid and comm.
	if len(fields) < 20 {
		return 0, false
	}
	ticks, err := strconv.ParseFloat(fields[19], 64)
	if err != nil {
		return 0, false
	}
	return boot + ticks/afAlgClockTicks, true
}

// afAlgClockTicks is USER_HZ, 100 on every architecture Linux ships for the
// platforms CSM runs on.
const afAlgClockTicks = 100.0
