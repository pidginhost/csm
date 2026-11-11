package webui

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/quarantinefs"
	"github.com/pidginhost/csm/internal/safepath"
)

// Exclusive file creation protects individual destinations, but a message's
// two entries and its progress record must also be handled as one operation.
var spoolRestoreMu sync.Mutex

type spoolRestoreState struct {
	Stage  string                 `json:"stage"`
	Header checks.QuarantineMeta  `json:"header"`
	Body   *checks.QuarantineMeta `json:"body,omitempty"`
}

func spoolRestoreBase(entry quarantineEntryRef) string {
	for _, suffix := range []string{"-H", "-D"} {
		if base, ok := strings.CutSuffix(entry.ItemPath, suffix); ok {
			return base
		}
	}
	return ""
}

func readSpoolRestoreState(base string) (*spoolRestoreState, error) {
	// #nosec G304 -- base comes from resolveQuarantineEntry under the operator-owned quarantine directory.
	data, err := os.ReadFile(base + ".restore")
	if err != nil {
		return nil, err
	}
	var state spoolRestoreState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if filepath.Base(state.Stage) != state.Stage || !strings.HasPrefix(state.Stage, ".csm-restore-") {
		return nil, fmt.Errorf("invalid mail restore staging directory")
	}
	return &state, nil
}

// Cleanup can fail after either sidecar has been removed. The durable progress
// record lets either original ID finish cleanup without requeueing the message.
func (s *Server) resumeQuarantinedSpoolMessage(w http.ResponseWriter, r *http.Request, entry quarantineEntryRef) bool {
	base := spoolRestoreBase(entry)
	if base == "" {
		return false
	}
	spoolRestoreMu.Lock()
	defer spoolRestoreMu.Unlock()
	state, err := readSpoolRestoreState(base)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		writeRestoreError(w, err)
	} else {
		s.finishQuarantinedSpoolMessage(w, r, base, state)
	}
	return true
}

func (s *Server) restoreQuarantinedSpoolMessage(w http.ResponseWriter, r *http.Request, entry quarantineEntryRef, meta checks.QuarantineMeta) {
	spoolRestoreMu.Lock()
	defer spoolRestoreMu.Unlock()
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
	if state, err := readSpoolRestoreState(base); err == nil {
		s.finishQuarantinedSpoolMessage(w, r, base, state)
		return
	} else if !os.IsNotExist(err) {
		writeRestoreError(w, err)
		return
	}
	if !quarantineEntryDeletable(entry) {
		writeJSONError(w, "Quarantine entry not found", http.StatusNotFound)
		return
	}

	state := &spoolRestoreState{}
	for _, want := range []string{"-D", "-H"} {
		other, err := readQuarantineMeta(base + want + ".meta")
		if errors.Is(err, os.ErrNotExist) && want == "-D" {
			// A partial quarantine can leave the original body in the spool.
			// An orphaned archive is not proof that the body was restored.
			if _, statErr := os.Lstat(base + want); os.IsNotExist(statErr) {
				continue
			}
		}
		if err != nil {
			writeRestoreError(w, err)
			return
		}
		otherDir, otherSuffix, err := checks.QuarantinedSpoolFile(*other)
		if err != nil || otherDir != spoolDir || otherSuffix != want || other.MessageID != meta.MessageID {
			writeJSONError(w, "Quarantined header and body belong to different messages", http.StatusConflict)
			return
		}
		if want == "-D" {
			state.Body = other
		} else {
			state.Header = *other
		}
	}
	for _, suffix := range []string{"-D", "-H"} {
		if _, err := validateQuarantineRestorePath(filepath.Join(spoolDir, meta.MessageID+suffix), []string{spoolDir}); err != nil {
			writeJSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := prepareSpoolRestore(base, spoolDir, state); err != nil {
		writeRestoreError(w, err)
		return
	}
	s.finishQuarantinedSpoolMessage(w, r, base, state)
}

func prepareSpoolRestore(base, spoolDir string, state *spoolRestoreState) error {
	target, targetErr := safepath.OpenTarget(spoolDir, state.Header.MessageID+"-H", false)
	if targetErr != nil {
		return targetErr
	}
	defer target.Close()
	if err := requireSpoolHeaderAbsent(target); err != nil {
		return err
	}
	if state.Body == nil {
		if err := checkRestoredSpoolBody(target.Parent, state.Header.MessageID, ""); err != nil {
			return err
		}
	}
	stage, name, stageErr := target.Parent.CreatePrivateTemp()
	if stageErr != nil {
		return stageErr
	}
	state.Stage = name
	retained := false
	defer func() {
		if !retained {
			_ = stage.Remove("-D")
			_ = stage.Remove("-H")
		}
		_ = stage.Close()
		if !retained {
			_ = target.Parent.RemoveDir(name)
		}
	}()
	for _, suffix := range []string{"-D", "-H"} {
		meta := &state.Header
		if suffix == "-D" {
			meta = state.Body
		}
		if meta == nil {
			continue
		}
		info, err := os.Lstat(base + suffix)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("quarantined spool file is not a regular file")
		}
		staged, err := safepath.OpenTarget(spoolDir, filepath.Join(name, suffix), false)
		if err != nil {
			return err
		}
		mode := os.FileMode(0640)
		if len(meta.Mode) >= 10 {
			mode = parseModeString(meta.Mode)
		}
		err = restoreQuarantineFile(base+suffix, meta.OriginalPath, staged, mode, *meta)
		staged.Close()
		if err != nil {
			return err
		}
	}
	if err := target.Parent.Sync(); err != nil {
		return err
	}
	data, encodeErr := json.Marshal(state)
	if encodeErr != nil {
		return encodeErr
	}
	writeErr := quarantinefs.WriteExclusive(base+".restore", bytes.NewReader(data), 0600)
	// A directory sync failure can leave a valid record. Its staged files
	// must survive so the next request can resume it.
	_, statErr := os.Lstat(base + ".restore")
	retained = statErr == nil
	return writeErr
}

func requireSpoolHeaderAbsent(target *safepath.Target) error {
	if _, err := target.Parent.Stat(target.Name); !os.IsNotExist(err) {
		return restoreFailed(http.StatusConflict, "Cannot restore - mail header already exists or cannot be inspected")
	}
	return target.Check()
}

func (s *Server) finishQuarantinedSpoolMessage(w http.ResponseWriter, r *http.Request, base string, state *spoolRestoreState) {
	if err := publishSpoolRestore(base, state); err != nil {
		writeRestoreError(w, err)
		return
	}
	messagePath := strings.TrimSuffix(state.Header.OriginalPath, "-H")
	s.auditLog(r, "restore", messagePath, "quarantined mail message returned to the queue")
	writeOK(w, map[string]interface{}{
		"path":    messagePath,
		"warning": "Message returned to the mail queue; it is delivered on the next queue run.",
	})
}

func publishSpoolRestore(base string, state *spoolRestoreState) error {
	spoolDir, suffix, checkErr := checks.QuarantinedSpoolFile(state.Header)
	if checkErr != nil || suffix != "-H" {
		return fmt.Errorf("invalid mail restore header metadata")
	}
	if state.Body != nil {
		dir, suffix, err := checks.QuarantinedSpoolFile(*state.Body)
		if err != nil || dir != spoolDir || suffix != "-D" || state.Body.MessageID != state.Header.MessageID {
			return fmt.Errorf("invalid mail restore body metadata")
		}
	}
	target, err := safepath.OpenTarget(spoolDir, state.Header.MessageID+"-H", false)
	if err != nil {
		return err
	}
	defer target.Close()
	stage, err := target.Parent.Walk(state.Stage)
	if os.IsNotExist(err) && spoolRestoreEvidenceRemoved(base, state) {
		return removeSpoolRestoreRecord(base)
	}
	if err != nil {
		return err
	}
	defer func() { _ = stage.Close() }()
	// The record and both staged files must be durable before any publication,
	// including a retry after an earlier directory sync failed.
	if err := quarantinefs.SyncDir(filepath.Dir(base)); err != nil {
		return err
	}
	if _, headerErr := stage.Stat("-H"); headerErr == nil {
		if err := requireSpoolHeaderAbsent(target); err != nil {
			return err
		}
		if state.Body != nil {
			if _, bodyErr := stage.Stat("-D"); bodyErr == nil {
				if err := stage.RenameTo("-D", target.Parent, state.Header.MessageID+"-D"); err != nil {
					return restoreFailed(http.StatusConflict, "Cannot publish restored body: %v", err)
				}
			} else if !os.IsNotExist(bodyErr) {
				return bodyErr
			}
		}
		archive := ""
		if state.Body != nil {
			archive = base + "-D"
		}
		if err := checkRestoredSpoolBody(target.Parent, state.Header.MessageID, archive); err != nil {
			return err
		}
		if err := syncSpoolPublication(target.Parent, stage); err != nil {
			return err
		}
		if err := stage.RenameTo("-H", target.Parent, target.Name); err != nil {
			return restoreFailed(http.StatusConflict, "Cannot publish restored header: %v", err)
		}
	} else if !os.IsNotExist(headerErr) {
		return headerErr
	}
	// A missing staged header means publication already happened. Exim may
	// have consumed the live message; never infer that it needs requeueing.
	if err := syncSpoolPublication(target.Parent, stage); err != nil {
		return err
	}
	for _, suffix := range []string{"-D", "-H"} {
		if suffix == "-D" && state.Body == nil {
			continue
		}
		if err := removeRestoredQuarantineEvidence(base+suffix, base+suffix+".meta"); err != nil {
			return fmt.Errorf("message returned to queue; retry to finish quarantine cleanup: %w", err)
		}
	}
	if err := target.Parent.RemoveDir(state.Stage); err != nil {
		return err
	}
	if err := target.Parent.Sync(); err != nil {
		return err
	}
	return removeSpoolRestoreRecord(base)
}

func syncSpoolPublication(parent, stage *safepath.Dir) error {
	return errors.Join(syncQuarantineRestoredParent(parent), stage.Sync())
}

func checkRestoredSpoolBody(parent *safepath.Dir, messageID, archive string) error {
	body, err := parent.OpenFile(messageID+"-D", os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("cannot restore header without its body: %w", err)
	}
	defer body.Close()
	info, err := body.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("mail body is not a regular file")
	}
	if archive != "" {
		// #nosec G304 -- archive is the paired body under the operator-owned quarantine directory, derived from resolveQuarantineEntry.
		source, err := os.Open(archive)
		if err != nil {
			return err
		}
		defer source.Close()
		liveHash, savedHash := sha256.New(), sha256.New()
		if _, err := io.Copy(liveHash, body); err != nil {
			return err
		}
		if _, err := io.Copy(savedHash, source); err != nil {
			return err
		}
		if !bytes.Equal(liveHash.Sum(nil), savedHash.Sum(nil)) {
			return restoreFailed(http.StatusConflict, "Restored mail body changed; quarantine retained")
		}
	}
	return nil
}

func spoolRestoreEvidenceRemoved(base string, state *spoolRestoreState) bool {
	for _, suffix := range []string{"-D", "-H"} {
		if suffix == "-D" && state.Body == nil {
			continue
		}
		for _, path := range []string{base + suffix, base + suffix + ".meta"} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				return false
			}
		}
	}
	return true
}

func removeSpoolRestoreRecord(base string) error {
	if err := os.Remove(base + ".restore"); err != nil {
		return err
	}
	return quarantinefs.SyncDir(filepath.Dir(base))
}
