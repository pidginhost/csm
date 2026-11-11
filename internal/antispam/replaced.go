package antispam

import (
	"net/url"
	"path"
	"strings"
	"time"
)

// ReplacedDir holds root-only backups of operator files CSM replaces.
// Retained copies are durable records: the daemon reports one warning per
// file found here.
const ReplacedDir = "/var/lib/csm/antispam/replaced"

// backupStamp is the UTC time that starts a backup name.
const backupStamp = "20060102T150405Z"

// Replacement is one operator file CSM replaced and the copy it kept.
type Replacement struct {
	Path, Backup string
}

// BackupName names the copy of target taken at at. The escaped path holds
// no "/", so every copy sits directly in ReplacedDir.
func BackupName(target string, at time.Time) string {
	return at.UTC().Format(backupStamp) + "_" + url.QueryEscape(target)
}

// ParseBackupName returns the absolute, clean target path a backup name was
// made for.
func ParseBackupName(name string) (string, bool) {
	stamp, escaped, ok := strings.Cut(name, "_")
	if !ok {
		return "", false
	}
	if _, err := time.Parse(backupStamp, stamp); err != nil {
		return "", false
	}
	target, err := url.QueryUnescape(escaped)
	if err != nil || !path.IsAbs(target) || path.Clean(target) != target {
		return "", false
	}
	return target, true
}
