//go:build linux

package daemon

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

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
	eventUID, err := strconv.ParseUint(ev.UID, 10, 32)
	if err != nil {
		return 0, false, "event carries no uid to verify"
	}

	exe, err := os.Readlink(fmt.Sprintf("%s/%d/exe", procRootDir, pid))
	if err != nil {
		return 0, false, "process is gone or its executable is unreadable"
	}
	// A deleted binary is reported as "<path> (deleted)".
	if exe != ev.Exe && strings.TrimSuffix(exe, " (deleted)") != ev.Exe {
		return 0, false, "pid now runs a different executable"
	}

	uid, ok := afAlgProcessUID(pid)
	if !ok {
		return 0, false, "process ownership unreadable"
	}
	if uid != eventUID {
		return 0, false, "pid now belongs to a different user"
	}

	eventAt, evErr := strconv.ParseFloat(ev.Timestamp, 64)
	if evErr != nil || math.IsNaN(eventAt) || math.IsInf(eventAt, 0) || eventAt <= 0 {
		return 0, false, "process start time could not be compared with the event"
	}
	startedBefore, ok := afAlgProcessStartedBefore(pid, eventAt)
	if !ok {
		return 0, false, "process start time could not be compared with the event"
	}
	if !startedBefore {
		return 0, false, "pid was recycled after the event"
	}
	return pid, true, ""
}

func afAlgProcessUID(pid int) (uint64, bool) {
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/status", procRootDir, pid))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		rest, found := strings.CutPrefix(line, "Uid:")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}
		uid, err := strconv.ParseUint(fields[0], 10, 32)
		return uid, err == nil
	}
	return 0, false
}

func afAlgProcessStartedBefore(pid int, eventAt float64) (bool, bool) {
	statData, err := os.ReadFile(fmt.Sprintf("%s/%d/stat", procRootDir, pid))
	if err != nil {
		return false, false
	}
	// The comm field is parenthesised and may contain spaces, so fields are
	// counted from after the closing parenthesis.
	close := strings.LastIndex(string(statData), ")")
	if close < 0 {
		return false, false
	}
	fields := strings.Fields(string(statData)[close+1:])
	// starttime is field 22 overall, which is index 19 after pid and comm.
	if len(fields) < 20 {
		return false, false
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return false, false
	}

	uptimeData, err := os.ReadFile(fmt.Sprintf("%s/uptime", procRootDir))
	if err != nil {
		return false, false
	}
	uptimeFields := strings.Fields(string(uptimeData))
	if len(uptimeFields) == 0 {
		return false, false
	}
	uptime, err := strconv.ParseFloat(uptimeFields[0], 64)
	if err != nil || math.IsNaN(uptime) || math.IsInf(uptime, 0) || uptime < 0 {
		return false, false
	}

	// Read wall time after uptime so the derived event uptime is conservative.
	// Ambiguous boundary cases fail closed instead of accepting a recycled PID.
	observedAt := float64(time.Now().UnixNano()) / float64(time.Second)
	elapsed := observedAt - eventAt
	if elapsed < 0 {
		return false, true
	}
	eventUptime := uptime - elapsed
	return eventUptime >= 0 && float64(ticks)/afAlgClockTicks <= eventUptime, true
}

// afAlgClockTicks is USER_HZ, 100 on every architecture Linux ships for the
// platforms CSM runs on.
const afAlgClockTicks = 100.0
