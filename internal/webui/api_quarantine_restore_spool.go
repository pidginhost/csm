package webui

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/checks"
)

type spoolRestoreHalf struct {
	entry quarantineEntryRef
	meta  checks.QuarantineMeta
	path  string
}

// restoreQuarantinedSpoolMessage returns a quarantined Exim message to the
// queue. Its header and body were quarantined as two entries; restoring either
// one restores both, body first, because Exim lists a message by its header.
func (s *Server) restoreQuarantinedSpoolMessage(w http.ResponseWriter, r *http.Request, entry quarantineEntryRef, meta checks.QuarantineMeta) {
	spoolDir, suffix, err := checks.QuarantinedSpoolFile(meta)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	base, ok := strings.CutSuffix(entry.ItemPath, suffix)
	if !ok {
		writeJSONError(w, "Quarantined spool file does not match its entry", http.StatusBadRequest)
		return
	}
	// Only the recorded directory: like the Fix that quarantined the
	// message, restore follows no symlink in the spool path.
	roots := []string{spoolDir}

	var halves []spoolRestoreHalf
	for _, want := range []string{"-D", "-H"} {
		half := spoolRestoreHalf{
			entry: quarantineEntryRef{ItemPath: base + want, MetaPath: base + want + ".meta"},
			meta:  meta,
		}
		if want != suffix {
			// The other half may be restored already, or the message had
			// no body file when it was quarantined.
			if !quarantineEntryDeletable(half.entry) {
				continue
			}
			other, readErr := readQuarantineMeta(half.entry.MetaPath)
			if readErr != nil {
				writeJSONError(w, readErr.Error(), http.StatusInternalServerError)
				return
			}
			otherDir, otherSuffix, checkErr := checks.QuarantinedSpoolFile(*other)
			if checkErr != nil || otherDir != spoolDir || otherSuffix != want || other.MessageID != meta.MessageID {
				writeJSONError(w, "Quarantined header and body belong to different messages", http.StatusConflict)
				return
			}
			half.meta = *other
		}
		half.path = filepath.Join(spoolDir, meta.MessageID+want)
		if _, pathErr := validateQuarantineRestorePath(half.path, roots); pathErr != nil {
			writeJSONError(w, pathErr.Error(), http.StatusBadRequest)
			return
		}
		halves = append(halves, half)
	}

	messagePath := filepath.Join(spoolDir, meta.MessageID)
	for i, half := range halves {
		if err := restoreQuarantinedSpoolFile(half, roots); err != nil {
			if i > 0 {
				err = fmt.Errorf("message body restored, header still in quarantine (restore it again): %w", err)
			}
			writeRestoreError(w, err)
			return
		}
	}
	s.auditLog(r, "restore", messagePath, "quarantined mail message returned to the queue")
	writeOK(w, map[string]interface{}{
		"path":    messagePath,
		"warning": "Message returned to the mail queue; it is delivered on the next queue run.",
	})
}

func restoreQuarantinedSpoolFile(half spoolRestoreHalf, roots []string) error {
	info, err := os.Lstat(half.entry.ItemPath)
	if err != nil {
		return restoreFailed(http.StatusInternalServerError, "Cannot stat quarantined file: %v", err)
	}
	if !info.Mode().IsRegular() {
		return restoreFailed(http.StatusInternalServerError, "Quarantined spool file is not a regular file")
	}
	target, err := openQuarantineRestoreTarget(half.path, roots, false)
	if err != nil {
		return restoreFailed(http.StatusConflict, "Cannot open restore destination: %v", err)
	}
	defer target.Close()
	if err := target.Check(); err != nil {
		return restoreFailed(http.StatusConflict, "%s", err.Error())
	}
	mode := os.FileMode(0640)
	if len(half.meta.Mode) >= 10 {
		mode = parseModeString(half.meta.Mode)
	}
	if err := restoreQuarantineFile(half.entry.ItemPath, half.path, target, mode, half.meta); err != nil {
		return err
	}
	return removeRestoredQuarantineEvidence(half.entry.ItemPath, half.entry.MetaPath)
}
