package daemon

import (
	"path/filepath"

	"github.com/pidginhost/csm/internal/actionlog"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// defaultLogDir is the directory the packaged unit creates for CSM's logs.
const defaultLogDir = "/var/log/csm"

// actionLogPath puts the action log beside the SIEM audit log, so an operator
// who moved that file gets both streams in one directory.
func actionLogPath(cfg *config.Config) string {
	dir := defaultLogDir
	if configured := cfg.Alerts.AuditLog.File.Path; configured != "" {
		dir = filepath.Dir(configured)
	}
	return actionlog.DefaultPath(dir)
}

// installActionLog points the process-wide action recorder at the log file.
// Every subsystem that changes host state records through it, so this runs
// before the watchers and the check scheduler start.
func (d *Daemon) installActionLog() {
	path := actionLogPath(d.cfg)
	sink := actionlog.NewFileSink(func() string { return path }, func(err error) {
		csmlog.Warn("action log write failed", "path", path, "err", err)
	})
	actionlog.SetSink(sink, d.cfg.Hostname)
}
