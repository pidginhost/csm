package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/quarantinefs"
	"github.com/pidginhost/csm/internal/safepath"
	"github.com/pidginhost/csm/internal/store"
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
	var timer backupTimer
	for {
		select {
		case <-d.stopCh:
			return
		case now := <-ticker.C:
			timer.tick(d, now)
		}
	}
}

type backupTimer struct {
	config config.BackupConfig
	last   time.Time
}

func (t *backupTimer) tick(d *Daemon, now time.Time) {
	cfg := d.currentCfg()
	if cfg.Backup != t.config {
		t.last = time.Time{}
		t.config = cfg.Backup
	}
	t.last = d.runBackupIfDue(cfg, now, t.last)
}

// runBackupIfDue exports once a full schedule has passed since both the last
// attempt and the newest archive on disk, so a restart keeps the cadence. It
// prunes only after a successful export: failing exports must never delete
// the last good archive. It returns the time the next schedule counts from.
func (d *Daemon) runBackupIfDue(cfg *config.Config, now, last time.Time) time.Time {
	if cfg == nil || !cfg.Backup.Enabled {
		return last
	}
	plan, err := config.ParseBackup(cfg)
	if err != nil {
		// Startup reports the invalid plan and continues monitoring.
		return last
	}
	if !last.After(now) && now.Before(last.Add(plan.Every)) {
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
	if err = checkBackupSources(plan.Dir, cfg); err != nil {
		return fail(err)
	}
	lock, err := lockBackupRoot(plan.Root, syscall.LOCK_EX)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		// Another export owns this destination. Check again next tick.
		return last
	}
	if err != nil {
		return fail(err)
	}
	defer lock.Close()
	archives, err := recoverAndListBackupArchives(plan)
	if err != nil {
		return fail(err)
	}
	var newest time.Time
	for name, at := range archives {
		// A future-dated archive, left by a clock that ran ahead, must not
		// hold off every export until that date.
		if at.After(newest) && !at.After(now) {
			// Older exports could die after creating the final name.
			info, statErr := os.Lstat(filepath.Join(plan.Dir, name+".sha256"))
			if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
				return fail(statErr)
			}
			if statErr == nil && info.Mode().IsRegular() {
				newest = at
			}
		}
	}
	if now.Before(newest.Add(plan.Every)) {
		return newest
	}

	path := filepath.Join(plan.Dir, plan.ArchiveName(now))
	size, err := publishBackup(cfg, path, d.exportStore)
	if err != nil {
		return fail(err)
	}
	csmlog.Info("scheduled backup written", "path", path, "bytes", size)

	cutoff := now.Add(-plan.Retention)
	for name, at := range archives {
		if !at.Before(cutoff) {
			continue
		}
		old := filepath.Join(plan.Dir, name)
		if err := pruneBackup(old); err != nil {
			csmlog.Warn("scheduled backup: removing an expired archive failed", "path", old, "err", err)
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

// Recover interrupted exports before using completed archives to set the cadence.
func recoverAndListBackupArchives(plan config.BackupPlan) (map[string]time.Time, error) {
	entries, err := os.ReadDir(plan.Dir)
	if err != nil {
		return nil, err
	}
	archives := make(map[string]time.Time)
	for _, e := range entries {
		path := filepath.Join(plan.Dir, e.Name())
		if e.IsDir() && strings.HasPrefix(e.Name(), backupStagePrefix) && backupTimestamp.MatchString(e.Name()) {
			if err := cleanBackupStage(path); err != nil {
				return nil, err
			}
		}
		if !e.Type().IsRegular() {
			continue
		}
		if backupScratch.MatchString(e.Name()) {
			if err := os.Remove(path); err != nil {
				return nil, err
			}
			continue
		}
		if at, ok := plan.ArchiveTime(e.Name()); ok {
			archives[e.Name()] = at
		}
	}
	return archives, nil
}

const backupStagePrefix = ".csm-b-"

var (
	backupTimestamp = regexp.MustCompile(`[0-9]{8}T[0-9]{6}Z`)
	backupScratch   = regexp.MustCompile(`^(csm-export-bbolt-[0-9]+\.snap|\.session-free-[0-9]+)$`)
)

func pruneBackup(path string) error {
	// Keep the archive discoverable for retry until its checksum is gone.
	checksum := path + ".sha256"
	info, err := os.Lstat(checksum)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err == nil && info.Mode().IsRegular() {
		if err = syscall.Unlink(checksum); err != nil {
			return err
		}
	}
	return syscall.Unlink(path)
}

// A tenant can flock a readable directory. Lock a private inode in CSM's
// trusted root and keep it there so all exporters lock the same inode.
func lockBackupRoot(root string, how int) (*os.File, error) {
	path := filepath.Join(root, ".csm-scheduled-export.lock")
	// #nosec G304 -- a fixed name in the checked CSM root, opened without following links.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid()) {
		err = fmt.Errorf("unsafe backup lock %s", path)
	}
	if err == nil {
		// #nosec G115 -- an open POSIX file descriptor fits in int.
		err = syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// Only a direct control export inside the backup root can leave a loose snapshot
// in a scheduled destination. Normal CLI exports have a private request directory.
func lockDirectExport(dir string) (*os.File, error) {
	root := config.BackupRoot()
	realRoot, err := filepath.EvalSymlinks(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || !safepath.Within(resolved, realRoot) {
		return nil, err
	}
	if err = ensureBackupDir(root, root); err != nil {
		return nil, err
	}
	return lockBackupRoot(root, syscall.LOCK_SH)
}

func checkBackupSources(dir string, cfg *config.Config) error {
	dest, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	for _, src := range []string{cfg.StatePath, cfg.Signatures.RulesDir} {
		if src == "" {
			continue
		}
		resolved, err := filepath.EvalSymlinks(src)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		source, err := filepath.Abs(resolved)
		if err != nil {
			return err
		}
		if safepath.Within(dest, source) {
			return fmt.Errorf("%s is inside state_path or signatures.rules_dir (%s)", dir, src)
		}
	}
	return nil
}

// The archive name is the commit point. Both files are complete before either
// link appears. Link refuses to overwrite a pre-existing destination.
func publishBackup(cfg *config.Config, path string, export func(*config.Config, string) (*store.ExportResult, error)) (size int64, err error) {
	name := filepath.Base(path)
	stage := filepath.Join(filepath.Dir(path), backupStagePrefix+name)
	if err = os.Mkdir(stage, 0o700); err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, cleanBackupStage(stage)) }()
	if err = checkBackupSources(stage, cfg); err != nil {
		return 0, err
	}
	part := filepath.Join(stage, name)
	res, err := export(cfg, part)
	if err != nil {
		return 0, err
	}
	if err = os.Link(part+".sha256", path+".sha256"); err != nil {
		return 0, err
	}
	if err = os.Link(part, path); err != nil {
		return 0, errors.Join(err, os.Remove(path+".sha256"))
	}
	return res.Bytes, quarantinefs.SyncDir(filepath.Dir(path))
}

// Recovery runs under the destination lock. Remove only this run's files and
// the store's temporary snapshots. The staged sidecar identifies by inode a
// checksum linked just before the daemon died publishing the archive.
func cleanBackupStage(stage string) error {
	name := strings.TrimPrefix(filepath.Base(stage), backupStagePrefix)
	info, err := os.Lstat(stage)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return nil
	}
	entries, err := os.ReadDir(stage)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		n := entry.Name()
		if !entry.Type().IsRegular() || (n != name && n != name+".sha256" && !backupScratch.MatchString(n)) {
			// An operator directory that happens to share our prefix.
			return nil
		}
	}
	path := filepath.Join(filepath.Dir(stage), name)
	part := filepath.Join(stage, name)
	if _, err = os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		linked, linkErr := sameBackupFile(part+".sha256", path+".sha256")
		if linkErr != nil {
			return linkErr
		}
		if linked {
			if err = os.Remove(path + ".sha256"); err != nil {
				return err
			}
		}
	} else if err != nil {
		return err
	}

	for _, entry := range entries {
		if err := os.Remove(filepath.Join(stage, entry.Name())); err != nil {
			return err
		}
	}
	return os.Remove(stage)
}

// A missing link is normal before publication or after cleanup.
func sameBackupFile(first, second string) (bool, error) {
	a, err := os.Lstat(first)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	b, err := os.Lstat(second)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return os.SameFile(a, b), err
}
