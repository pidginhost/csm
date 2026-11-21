package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/safepath"
)

// BackupConfig schedules the store export the daemon runs on its own and the
// pruning of the archives it leaves.
type BackupConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Schedule       string `yaml:"schedule"`        // Go duration between exports; at least 1h
	DestinationDir string `yaml:"destination_dir"` // must sit inside the backup root
	Filename       string `yaml:"filename"`        // {date} expands to the run's UTC start time
	RetentionDays  int    `yaml:"retention_days"`  // archives older than this are deleted
}

// backupRoot is the CSM-owned tree the service unit lets the daemon write
// (StateDirectory=csm). Anywhere else ProtectSystem=strict makes read-only or
// belongs to someone else.
var backupRoot = "/var/lib/csm"

// BackupRoot is the common parent of all scheduled destinations.
func BackupRoot() string { return backupRoot }

// SetBackupRoot points the backup root elsewhere and returns a func restoring
// the previous one. Tests use it to stay hermetic.
func SetBackupRoot(path string) func() {
	previous := backupRoot
	backupRoot = path
	return func() { backupRoot = previous }
}

// backupDateLayout is what {date} expands to. Second resolution keeps names
// unique, since runs are at least an hour apart.
const backupDateLayout = "20060102T150405Z"

const maxBackupRetentionDays = 3650

// BackupPlan is a backup block that passed ParseBackup.
type BackupPlan struct {
	Every     time.Duration
	Root      string
	Dir       string
	Retention time.Duration
	prefix    string
	suffix    string
}

// ParseBackup checks the backup block and returns the plan the scheduler runs.
func ParseBackup(cfg *Config) (BackupPlan, error) {
	b := cfg.Backup
	every, err := time.ParseDuration(b.Schedule)
	if err != nil || every < time.Hour {
		return BackupPlan{}, fmt.Errorf("backup.schedule must be a duration of at least 1h, got %q", b.Schedule)
	}
	dir := b.DestinationDir
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return BackupPlan{}, fmt.Errorf("backup.destination_dir must be an absolute path without . or .. components or a trailing slash, got %q", dir)
	}
	if !safepath.Within(dir, backupRoot) {
		return BackupPlan{}, fmt.Errorf("backup.destination_dir %s is outside %s, the only CSM directory the daemon's service sandbox can write; copy archives elsewhere from there", dir, backupRoot)
	}
	if safepath.Within(dir, cfg.StatePath) || safepath.Within(dir, cfg.Signatures.RulesDir) {
		return BackupPlan{}, fmt.Errorf("backup.destination_dir %s is inside state_path or signatures.rules_dir, which every export copies", dir)
	}
	prefix, suffix, found := strings.Cut(b.Filename, "{date}")
	if !found || strings.Contains(suffix, "{date}") || strings.ContainsAny(b.Filename, "/\x00\r\n") {
		return BackupPlan{}, fmt.Errorf("backup.filename must contain {date} exactly once and be a single filename suitable for a checksum line, got %q", b.Filename)
	}
	if b.RetentionDays < 1 || b.RetentionDays > maxBackupRetentionDays {
		return BackupPlan{}, fmt.Errorf("backup.retention_days must be between 1 and %d, got %d", maxBackupRetentionDays, b.RetentionDays)
	}
	return BackupPlan{
		Every:     every,
		Root:      backupRoot,
		Dir:       dir,
		Retention: time.Duration(b.RetentionDays) * 24 * time.Hour,
		prefix:    prefix,
		suffix:    suffix,
	}, nil
}

// ArchiveName names the archive of a run that started at t.
func (p BackupPlan) ArchiveName(t time.Time) string {
	return p.prefix + t.UTC().Format(backupDateLayout) + p.suffix
}

// ArchiveTime returns the start time of the run that wrote name. ok is false
// for any name the filename pattern cannot produce, which is what keeps
// pruning away from every other file in the directory.
func (p BackupPlan) ArchiveTime(name string) (time.Time, bool) {
	stamp, hasPrefix := strings.CutPrefix(name, p.prefix)
	stamp, hasSuffix := strings.CutSuffix(stamp, p.suffix)
	if !hasPrefix || !hasSuffix {
		return time.Time{}, false
	}
	t, err := time.Parse(backupDateLayout, stamp)
	if err != nil || t.Format(backupDateLayout) != stamp {
		return time.Time{}, false
	}
	return t, true
}
