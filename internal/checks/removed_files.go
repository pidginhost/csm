package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

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
	var saved []RemovedFile
	data, err := osFS.ReadFile(path)
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
	for _, r := range saved {
		if !filepath.IsAbs(r.Path) || (r.Action != "quarantine" && r.Action != "clean") ||
			r.Size < 0 || r.At.IsZero() || now.Sub(r.At) >= removedFileMemory {
			continue
		}
		r.Path, r.Seq = filepath.Clean(r.Path), 0
		if current, ok := removedFiles.byPath[r.Path]; ok && !current.At.Before(r.At) {
			continue
		}
		removedFiles.byPath[r.Path] = r
	}
}

// saveRemovedFiles writes the ledger to its state file, if it has one.
func saveRemovedFiles() {
	removedFilesWrite.Lock()
	defer removedFilesWrite.Unlock()
	removedFiles.RLock()
	path := removedFiles.path
	list := make([]RemovedFile, 0, len(removedFiles.byPath))
	for _, r := range removedFiles.byPath {
		list = append(list, r)
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
