package firewall

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

const maxAuditFileSize = 10 * 1024 * 1024 // 10 MB

// AuditEntry records a firewall modification for compliance and forensics.
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"` // block, unblock, allow, remove_allow, flush, apply
	IP        string    `json:"ip,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Source    string    `json:"source,omitempty"`
	Duration  string    `json:"duration,omitempty"`
}

// AppendAudit writes an audit entry to the JSONL audit log.
// Rotates the log when it exceeds 10 MB.
func AppendAudit(statePath, action, ip, reason, source string, duration time.Duration) {
	if source == "" {
		source = InferProvenance(action, reason)
	}
	entry := AuditEntry{
		Timestamp: time.Now(),
		Action:    action,
		IP:        ip,
		Reason:    reason,
		Source:    source,
	}
	if duration > 0 {
		entry.Duration = duration.String()
	}

	path := filepath.Join(statePath, "audit.jsonl")
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	// Rotate if file exceeds max size
	if info, statErr := os.Stat(path); statErr == nil && info.Size() > maxAuditFileSize {
		_ = os.Rename(path, path+".1")
	}

	// #nosec G304 -- path is filepath.Join under operator-configured statePath.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		// Without this log, perm/disk-full/inode-exhaust modes drop the
		// audit entry with no operator-visible signal -- the Write/Close
		// branches below already log, so a silent Open path was the only
		// remaining hole in the audit pipeline.
		log.Printf("firewall: audit open failed for %s: %v", path, err)
		return
	}
	if _, writeErr := f.Write(data); writeErr != nil {
		_ = f.Close()
		log.Printf("firewall: audit write failed for %s: %v", path, writeErr)
		return
	}
	// Close error on a writable file is the disk-full / fsync signal --
	// without it, a dropped audit entry leaves no record anywhere.
	if closeErr := f.Close(); closeErr != nil {
		log.Printf("firewall: audit close failed for %s: %v", path, closeErr)
	}
}

// ReadAuditLog returns the last N audit entries from the log.
func ReadAuditLog(statePath string, limit int) []AuditEntry {
	path := filepath.Join(statePath, "firewall", "audit.jsonl")
	// #nosec G304 -- filepath.Join under operator-configured statePath.
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var all []AuditEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry AuditEntry
		if json.Unmarshal(scanner.Bytes(), &entry) == nil {
			all = append(all, entry)
		}
	}

	if limit > 0 && len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all
}
