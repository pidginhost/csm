//go:build linux

package daemon

import (
	"strconv"

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
	pid, err := strconv.Atoi(ev.PID)
	if err != nil || pid <= 1 {
		csmlog.Warn("af_alg react: refusing to kill",
			"reason", "implausible pid",
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
