package emailav

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// QuarantineEnvelope holds the email envelope info for quarantine metadata.
type QuarantineEnvelope struct {
	From      string
	To        []string
	Subject   string
	Direction string
}

// QuarantineMetadata is the JSON sidecar written with quarantined messages.
type QuarantineMetadata struct {
	MessageID        string    `json:"message_id"`
	Direction        string    `json:"direction"`
	From             string    `json:"from"`
	To               []string  `json:"to"`
	Subject          string    `json:"subject"`
	QuarantinedAt    time.Time `json:"quarantined_at"`
	OriginalSpoolDir string    `json:"original_spool_dir"`
	Findings         []Finding `json:"findings"`
	PartialScan      bool      `json:"partial_scan"`
	EnginesUsed      []string  `json:"engines_used"`
}

// Quarantine manages the per-message email quarantine directory.
type Quarantine struct {
	baseDir string // e.g. /opt/csm/quarantine/email
}

// NewQuarantine creates a quarantine manager for the given base directory.
func NewQuarantine(baseDir string) *Quarantine {
	return &Quarantine{baseDir: baseDir}
}

// QuarantineMessage moves spool files into a per-message quarantine directory
// and writes metadata.json.
func (q *Quarantine) QuarantineMessage(msgID, spoolDir string, result *ScanResult, env QuarantineEnvelope) error {
	msgDir := filepath.Join(q.baseDir, msgID)
	if err := os.MkdirAll(msgDir, 0700); err != nil {
		return fmt.Errorf("creating quarantine dir: %w", err)
	}

	// Move spool files
	moved := 0
	for _, suffix := range []string{"-H", "-D"} {
		src := filepath.Join(spoolDir, msgID+suffix)
		dst := filepath.Join(msgDir, msgID+suffix)
		if err := moveFile(src, dst); err != nil {
			continue
		}
		moved++
	}
	if moved == 0 {
		os.Remove(msgDir)
		return fmt.Errorf("no spool files found for %s", msgID)
	}

	// Write metadata
	meta := QuarantineMetadata{
		MessageID:        msgID,
		Direction:        env.Direction,
		From:             env.From,
		To:               env.To,
		Subject:          env.Subject,
		QuarantinedAt:    time.Now(),
		OriginalSpoolDir: spoolDir,
		Findings:         result.Findings,
		PartialScan:      result.PartialExtraction,
		EnginesUsed:      result.EnginesUsed,
	}

	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}
	metaPath := filepath.Join(msgDir, "metadata.json")
	if err := os.WriteFile(metaPath, metaData, 0600); err != nil {
		return fmt.Errorf("writing metadata: %w", err)
	}

	return nil
}

// ListMessages returns all quarantined email messages.
func (q *Quarantine) ListMessages() ([]QuarantineMetadata, error) {
	entries, err := os.ReadDir(q.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading quarantine dir: %w", err)
	}

	var msgs []QuarantineMetadata
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		meta, err := q.readMetadata(entry.Name())
		if err != nil {
			continue
		}
		msgs = append(msgs, *meta)
	}
	return msgs, nil
}

// GetMessage returns the metadata for a single quarantined message.
func (q *Quarantine) GetMessage(msgID string) (*QuarantineMetadata, error) {
	return q.readMetadata(msgID)
}

// ReleaseMessage moves spool files back to the original spool directory
// and removes the quarantine directory.
func (q *Quarantine) ReleaseMessage(msgID string) error {
	meta, err := q.readMetadata(msgID)
	if err != nil {
		return fmt.Errorf("reading metadata: %w", err)
	}

	msgDir := filepath.Join(q.baseDir, msgID)
	for _, suffix := range []string{"-H", "-D"} {
		src := filepath.Join(msgDir, msgID+suffix)
		dst := filepath.Join(meta.OriginalSpoolDir, msgID+suffix)
		if err := moveFile(src, dst); err != nil {
			// If source doesn't exist, skip (partial quarantine)
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("moving %s back to spool: %w", suffix, err)
		}
	}

	return os.RemoveAll(msgDir)
}

// DeleteMessage permanently removes a quarantined message.
func (q *Quarantine) DeleteMessage(msgID string) error {
	msgDir := filepath.Join(q.baseDir, filepath.Base(msgID)) // sanitize
	return os.RemoveAll(msgDir)
}

// CleanExpired removes quarantine directories older than maxAge.
// Returns the number of directories cleaned.
func (q *Quarantine) CleanExpired(maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(q.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	cleaned := 0
	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		meta, err := q.readMetadata(entry.Name())
		if err != nil {
			continue
		}
		if meta.QuarantinedAt.Before(cutoff) {
			os.RemoveAll(filepath.Join(q.baseDir, entry.Name()))
			cleaned++
		}
	}
	return cleaned, nil
}

func (q *Quarantine) readMetadata(msgID string) (*QuarantineMetadata, error) {
	metaPath := filepath.Join(q.baseDir, msgID, "metadata.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var meta QuarantineMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// moveFile renames src to dst, falling back to copy+delete for cross-device moves.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		// Cross-device fallback
		data, readErr := os.ReadFile(src)
		if readErr != nil {
			return readErr
		}
		if writeErr := os.WriteFile(dst, data, 0600); writeErr != nil {
			return writeErr
		}
		os.Remove(src)
	}
	return nil
}
