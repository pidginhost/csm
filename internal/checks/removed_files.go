package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/atomicio"
)

// RemovedFile is content a file response took away from a path: the bytes a
// quarantine moved out or a clean replaced.
type RemovedFile struct {
	Path   string    `json:"path"`
	SHA256 string    `json:"sha256,omitempty"`
	Size   int64     `json:"size"`
	At     time.Time `json:"at"`
	// Action is "quarantine" or "clean".
	Action string `json:"action"`
	// Seq orders removals within this process. Loaded removals have none.
	Seq uint64 `json:"-"`
}

// JSON replaces invalid UTF-8 in strings. Keep those Linux path bytes separate
// so a restart cannot bind the removal to a different file.
type savedRemovedFile struct {
	RemovedFile
	PathBytes []byte `json:"path_bytes,omitempty"`
}

func savedRemoval(r RemovedFile) savedRemovedFile {
	saved := savedRemovedFile{RemovedFile: r}
	if !utf8.ValidString(r.Path) {
		saved.PathBytes = []byte(r.Path)
		saved.Path = ""
	}
	return saved
}

func (s savedRemovedFile) removal(now time.Time) (RemovedFile, bool) {
	r := s.RemovedFile
	if s.PathBytes != nil {
		if r.Path != "" {
			return RemovedFile{}, false
		}
		r.Path = string(s.PathBytes)
	}
	r.Seq = 0
	return r, validRemovedFile(r, now)
}

// removedFilesStateName keeps the ledger across daemon restarts.
const removedFilesStateName = "removed-files.json"

// RestoreKey binds a finding to the removal it observed, including across
// restarts, when the in-memory sequence starts over.
func (r RemovedFile) RestoreKey() string {
	return fmt.Sprintf("%s:removed-%d", r.Path, r.At.UnixNano())
}

// removedFileMemory is how long a removal stays recognisable. A restore loop
// can outwait an operator for days; entries are small and their number is
// bounded by the file response budget and by operator actions.
const removedFileMemory = 7 * 24 * time.Hour

var removedFilesNow = time.Now

// removedFiles is saved to path, once LoadRemovedFiles names it, on every
// change. Only the daemon loads it: other processes keep their removals in
// memory.
var removedFiles struct {
	sync.RWMutex
	byPath map[string]RemovedFile
	seq    uint64
	path   string
}

// removedFilesWrite orders saves; each one writes the ledger as it stands.
var removedFilesWrite sync.Mutex

// LoadRemovedFiles restores the removals saved under statePath and saves the
// ledger there from now on. Loaded removals are not reported again by
// RemovedFilesSince: their alert state was cleared when they happened.
func LoadRemovedFiles(statePath string) {
	if statePath == "" {
		return
	}
	path := filepath.Join(statePath, removedFilesStateName)
	var saved []savedRemovedFile
	data, err := readRemovedFilesState(path)
	switch {
	case err == nil:
		if uerr := json.Unmarshal(data, &saved); uerr != nil {
			fmt.Fprintf(os.Stderr, "removed files: %s is damaged, starting empty: %v\n", path, uerr)
			saved = nil
		}
	case !os.IsNotExist(err):
		fmt.Fprintf(os.Stderr, "removed files: reading %s: %v\n", path, err)
	}
	now := removedFilesNow()
	removedFiles.Lock()
	defer removedFiles.Unlock()
	removedFiles.path = path
	if removedFiles.byPath == nil {
		removedFiles.byPath = make(map[string]RemovedFile)
	}
	for _, entry := range saved {
		r, valid := entry.removal(now)
		if !valid {
			continue
		}
		if current, ok := removedFiles.byPath[r.Path]; ok && !current.At.Before(r.At) {
			continue
		}
		removedFiles.byPath[r.Path] = r
	}
}

// The file-action budget bounds normal ledger growth. This separate read bound
// prevents damaged state from exhausting memory before those records are checked.
const maxRemovedFilesStateBytes = 64 << 20

func readRemovedFilesState(path string) ([]byte, error) {
	file, err := openTenantRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !privateRemovedFilesState(info) {
		return nil, errors.New("removal state must be private and owned by the daemon user")
	}
	if info.Size() > maxRemovedFilesStateBytes {
		return nil, errors.New("removal state is too large")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxRemovedFilesStateBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRemovedFilesStateBytes {
		return nil, errors.New("removal state is too large")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("removal state contains invalid UTF-8")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !SameFileVersion(info, after) || !privateRemovedFilesState(after) {
		return nil, errFileChanged
	}
	return data, nil
}

func privateRemovedFilesState(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid() && info.Mode().IsRegular() && info.Mode().Perm() == 0o600
}

func validRemovedFile(r RemovedFile, now time.Time) bool {
	if !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path || strings.ContainsRune(r.Path, 0) ||
		(r.Action != "quarantine" && r.Action != "clean") || r.Size < 0 ||
		r.At.IsZero() || r.At.After(now) || now.Sub(r.At) >= removedFileMemory {
		return false
	}
	// Large removals can legitimately lack an audit digest. They still clear
	// alert state, but cannot authorize a repeat response without a content hash.
	if r.SHA256 == "" {
		return true
	}
	digest, err := hex.DecodeString(r.SHA256)
	return err == nil && len(digest) == sha256.Size && hex.EncodeToString(digest) == r.SHA256
}

// saveRemovedFiles writes the ledger to its state file, if it has one.
func saveRemovedFiles() {
	removedFilesWrite.Lock()
	defer removedFilesWrite.Unlock()
	removedFiles.RLock()
	path := removedFiles.path
	list := make([]savedRemovedFile, 0, len(removedFiles.byPath))
	for _, r := range removedFiles.byPath {
		list = append(list, savedRemoval(r))
	}
	removedFiles.RUnlock()
	if path == "" {
		return
	}
	if err := atomicio.AtomicWriteJSON(path, 0o600, list); err != nil {
		fmt.Fprintf(os.Stderr, "removed files: saving %s: %v\n", path, err)
	}
}

func rememberRemovedFile(path, digest string, size int64, action string) {
	if path == "" {
		return
	}
	now := removedFilesNow()
	path = filepath.Clean(path)
	removedFiles.Lock()
	if removedFiles.byPath == nil {
		removedFiles.byPath = make(map[string]RemovedFile)
	}
	for p, r := range removedFiles.byPath {
		if now.Sub(r.At) >= removedFileMemory {
			delete(removedFiles.byPath, p)
		}
	}
	removedFiles.seq++
	removedFiles.byPath[path] = RemovedFile{Path: path, SHA256: digest, Size: size, At: now, Action: action, Seq: removedFiles.seq}
	removedFiles.Unlock()
	saveRemovedFiles()
}

// RemovedFileAt reports the content CSM last removed from path, while that
// removal is recent enough to recognise.
func RemovedFileAt(path string) (RemovedFile, bool) {
	removedFiles.RLock()
	r, ok := removedFiles.byPath[filepath.Clean(path)]
	removedFiles.RUnlock()
	if !ok || removedFilesNow().Sub(r.At) >= removedFileMemory {
		return RemovedFile{}, false
	}
	return r, true
}

// RemovedFilesSince returns the removals recorded after seq and the sequence
// to pass on the next call.
func RemovedFilesSince(seq uint64) ([]RemovedFile, uint64) {
	removedFiles.RLock()
	defer removedFiles.RUnlock()
	var out []RemovedFile
	for _, r := range removedFiles.byPath {
		if r.Seq > seq {
			out = append(out, r)
		}
	}
	return out, removedFiles.seq
}

// ForgetRemovedFile drops path before an operator restores it, so the restore
// is not taken for the removed file coming back.
func ForgetRemovedFile(path string) {
	removedFiles.Lock()
	delete(removedFiles.byPath, filepath.Clean(path))
	removedFiles.Unlock()
	saveRemovedFiles()
}
