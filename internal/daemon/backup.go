package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// backupPollInterval is how often the scheduler reads the live backup block,
// so a reload that enables, disables or retimes it applies within a minute.
const backupPollInterval = time.Minute

// backupScheduler runs the store export on backup.schedule. It runs even while
// the block is disabled so that enabling it applies on reload.
func (d *Daemon) backupScheduler() {
	defer d.wg.Done()
	ticker := time.NewTicker(backupPollInterval)
	defer ticker.Stop()
	var last time.Time
	for {
		select {
		case <-d.stopCh:
			return
		case now := <-ticker.C:
			last = d.runBackupIfDue(now, last)
		}
	}
}

// runBackupIfDue exports once a full schedule has passed since both the last
// attempt and the newest archive on disk, so a restart keeps the cadence. It
// prunes only after a successful export: failing exports must never delete
// the last good archive. It returns the time the next schedule counts from.
func (d *Daemon) runBackupIfDue(now, last time.Time) time.Time {
	cfg := d.currentCfg()
	if cfg == nil || !cfg.Backup.Enabled {
		return last
	}
	plan, err := config.ParseBackup(cfg)
	if err != nil {
		// Validate refuses such a block at start and on reload.
		return last
	}
	if now.Before(last.Add(plan.Every)) {
		return last
	}
	fail := func(err error) time.Time {
		d.emitReloadFinding(alert.Warning, "backup_export_failed",
			fmt.Sprintf("scheduled backup to %s failed: %v; the next attempt is in %s", plan.Dir, err, plan.Every))
		return now
	}
	if err = ensureBackupDir(plan.Root, plan.Dir); err != nil {
		return fail(err)
	}
	archives, err := listBackupArchives(plan)
	if err != nil {
		return fail(err)
	}
	var newest time.Time
	for _, at := range archives {
		// A future-dated archive, left by a clock that ran ahead, must not
		// hold off every export until that date.
		if at.After(newest) && !at.After(now) {
			newest = at
		}
	}
	if now.Before(newest.Add(plan.Every)) {
		return newest
	}

	path := filepath.Join(plan.Dir, plan.ArchiveName(now))
	res, err := d.exportStore(path)
	if err != nil {
		return fail(err)
	}
	csmlog.Info("scheduled backup written", "path", path, "bytes", res.Bytes)

	cutoff := now.Add(-plan.Retention)
	for name, at := range archives {
		if !at.Before(cutoff) {
			continue
		}
		old := filepath.Join(plan.Dir, name)
		for _, p := range []string{old, old + ".sha256"} {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				csmlog.Warn("scheduled backup: removing an expired archive failed", "path", p, "err", err)
			}
		}
	}
	return now
}

// ensureBackupDir creates dir when missing and refuses it unless every
// directory from root down is a real directory, owned by root and not
// writable by group or others. The export writes by path, so a symlink or a
// directory another account can write would let that account redirect or
// replace the archive. Directories above root belong to the OS layout.
func ensureBackupDir(root, dir string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return err
	}
	path := root
	for _, part := range append([]string{"."}, strings.Split(rel, string(filepath.Separator))...) {
		path = filepath.Join(path, part)
		// The parent was checked first, so only root can be racing this.
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		switch {
		case !info.IsDir():
			return fmt.Errorf("%s is a symlink or not a directory", path)
		case !ok || int(st.Uid) != os.Geteuid(): // the daemon runs as root
			return fmt.Errorf("%s is not owned by root", path)
		case info.Mode().Perm()&0o022 != 0:
			return fmt.Errorf("%s is writable by group or others", path)
		}
	}
	return nil
}

// listBackupArchives returns the regular files in the destination that the
// block's filename pattern names, with the start time of the run behind each.
func listBackupArchives(plan config.BackupPlan) (map[string]time.Time, error) {
	entries, err := os.ReadDir(plan.Dir)
	if err != nil {
		return nil, err
	}
	archives := make(map[string]time.Time)
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if at, ok := plan.ArchiveTime(e.Name()); ok {
			archives[e.Name()] = at
		}
	}
	return archives, nil
}
