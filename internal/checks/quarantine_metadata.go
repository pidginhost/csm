package checks

import (
	"encoding/json"
	"os"
	"syscall"
	"time"
)

// QuarantineMeta stores original file metadata alongside quarantined files.
type QuarantineMeta struct {
	OriginalPath    string    `json:"original_path"`
	Owner           int       `json:"owner_uid"`
	Group           int       `json:"group_gid"`
	Mode            string    `json:"mode"`
	Size            int64     `json:"size"`
	QuarantineAt    time.Time `json:"quarantined_at"`
	OriginalModTime time.Time `json:"original_mtime,omitzero"`
	Reason          string    `json:"reason"`
	// FindingID ties the quarantine to the finding that caused it, using the
	// same identifier the audit log and the action log emit. Empty when the
	// quarantine came from an operator command rather than a detection.
	FindingID             string `json:"finding_id,omitempty"`
	MessageID             string `json:"message_id,omitempty"`
	SpoolDir              string `json:"spool_dir,omitempty"`
	RestoreAction         string `json:"restore_action,omitempty"`
	ExpectedCurrentSHA256 string `json:"expected_current_sha256,omitempty"`
}

// UnmarshalJSON accepts the timestamp spelling used by historical manual
// fixes. Missing original mtimes remain unknown; archive mtimes are not evidence
// of when the original was modified.
func (m *QuarantineMeta) UnmarshalJSON(data []byte) error {
	type wire QuarantineMeta
	var decoded struct {
		wire
		LegacyQuarantineAt time.Time `json:"quarantine_at"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if decoded.QuarantineAt.IsZero() {
		decoded.QuarantineAt = decoded.LegacyQuarantineAt
	}
	*m = QuarantineMeta(decoded.wire)
	return nil
}

func quarantineMetadata(path string, info os.FileInfo, reason string) QuarantineMeta {
	meta := QuarantineMeta{
		OriginalPath:    path,
		Mode:            info.Mode().String(),
		Size:            info.Size(),
		QuarantineAt:    time.Now().UTC(),
		OriginalModTime: info.ModTime().UTC(),
		Reason:          reason,
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		meta.Owner, meta.Group = int(stat.Uid), int(stat.Gid)
	}
	return meta
}
