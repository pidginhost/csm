package emailav

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type movedFile struct {
	src string
	dst string
}

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
	baseDir          string // e.g. /opt/csm/quarantine/email
	allowedSpoolDirs []string
}

// NewQuarantine creates a quarantine manager for the given base directory.
func NewQuarantine(baseDir string) *Quarantine {
	return &Quarantine{
		baseDir:          baseDir,
		allowedSpoolDirs: []string{"/var/spool/exim/input", "/var/spool/exim4/input"},
	}
}

// QuarantineMessage moves spool files into a per-message quarantine directory
// and writes metadata.json.
func (q *Quarantine) QuarantineMessage(msgID, spoolDir string, result *ScanResult, env QuarantineEnvelope) error {
	msgID = filepath.Base(msgID) // sanitize against path traversal
	msgDir := filepath.Join(q.baseDir, msgID)
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

	if err := os.MkdirAll(msgDir, 0700); err != nil {
		return fmt.Errorf("creating quarantine dir: %w", err)
	}

	var moved []movedFile
	for _, suffix := range []string{"-H", "-D"} {
		src := filepath.Join(spoolDir, msgID+suffix)
		dst := filepath.Join(msgDir, msgID+suffix)
		if err := moveFile(src, dst); err != nil {
			continue
		}
		moved = append(moved, movedFile{src: src, dst: dst})
	}
	if len(moved) == 0 {
		os.Remove(msgDir)
		return fmt.Errorf("no spool files found for %s", msgID)
	}

	metaPath := filepath.Join(msgDir, "metadata.json")
	if err := os.WriteFile(metaPath, metaData, 0600); err != nil {
		rollbackErr := rollbackMovedFiles(moved)
		_ = os.RemoveAll(msgDir)
		if rollbackErr != nil {
			return fmt.Errorf("writing metadata: %w (rollback failed: %v)", err, rollbackErr)
		}
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
	return q.readMetadata(filepath.Base(msgID))
}

// ReleaseMessage moves spool files back to the original spool directory
// and removes the quarantine directory.
func (q *Quarantine) ReleaseMessage(msgID string) error {
	msgID = filepath.Base(msgID) // sanitize against path traversal
	meta, err := q.readMetadata(msgID)
	if err != nil {
		return fmt.Errorf("reading metadata: %w", err)
	}
	spoolDir, err := q.validateReleaseSpoolDir(meta.OriginalSpoolDir)
	if err != nil {
		return err
	}

	msgDir := filepath.Join(q.baseDir, msgID)
	for _, suffix := range []string{"-H", "-D"} {
		src := filepath.Join(msgDir, msgID+suffix)
		dst := filepath.Join(spoolDir, msgID+suffix)
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
	msgID = filepath.Base(msgID) // defense in depth
	metaPath := filepath.Join(q.baseDir, msgID, "metadata.json")
	// #nosec G304 -- msgID sanitized with filepath.Base; filepath.Join under baseDir.
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

// moveFile renames src to dst, falling back to copy+delete for cross-device
// moves. Callers construct dst by filepath.Join under the quarantine base dir
// (config-owned) plus a filepath.Base-sanitized identifier.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		// Cross-device fallback
		// #nosec G304 -- src is mail queue path from scanner walk.
		data, readErr := os.ReadFile(src)
		if readErr != nil {
			return readErr
		}
		// #nosec G703 -- dst is constructed by the caller under the
		// quarantine baseDir with filepath.Base applied to any user-
		// supplied component (see readMetadata above for the pattern).
		if writeErr := os.WriteFile(dst, data, 0600); writeErr != nil {
			return writeErr
		}
		os.Remove(src)
	}
	return nil
}

func rollbackMovedFiles(moved []movedFile) error {
	for i := len(moved) - 1; i >= 0; i-- {
		if err := moveFile(moved[i].dst, moved[i].src); err != nil {
			return err
		}
	}
	return nil
}

func (q *Quarantine) validateReleaseSpoolDir(spoolDir string) (string, error) {
	cleanDir := filepath.Clean(spoolDir)
	if cleanDir == "" || !filepath.IsAbs(cleanDir) {
		return "", fmt.Errorf("invalid original spool directory")
	}
	// Fail closed when the supplied path will not resolve. The previous
	// behaviour fell back to the unresolved literal, which let a path
	// that does not currently exist on disk still match an allowed-list
	// entry that also does not exist (e.g. on a host where only one of
	// the default exim spool defaults is installed). A release that
	// targets a path we cannot resolve cannot have its identity
	// confirmed, so it must not proceed.
	resolvedDir, err := filepath.EvalSymlinks(cleanDir)
	if err != nil {
		return "", fmt.Errorf("resolving original spool directory %q: %w", cleanDir, err)
	}

	for _, allowed := range q.allowedSpoolDirs {
		cleanAllowed := filepath.Clean(allowed)
		// Allowed entries are operator-config trusted defaults; the
		// shipped list intentionally covers both exim and exim4, so a
		// host that only has one of them must silently skip the
		// non-installed entry rather than falling back to the literal
		// (which would silently widen the trust boundary). The input
		// path was already required to resolve above, so a missing
		// allowed entry can never alias the resolved input.
		resolvedAllowed, err := filepath.EvalSymlinks(cleanAllowed)
		if err != nil {
			continue
		}
		if resolvedDir == resolvedAllowed {
			return resolvedDir, nil
		}
	}

	return "", fmt.Errorf("original spool directory is not trusted: %s", cleanDir)
}
