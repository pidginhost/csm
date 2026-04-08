package firewall

import (
	"bufio"
	"encoding/json"
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

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(data)
}

// ReadAuditLog returns the last N audit entries from the log.
func ReadAuditLog(statePath string, limit int) []AuditEntry {
	path := filepath.Join(statePath, "firewall", "audit.jsonl")
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
