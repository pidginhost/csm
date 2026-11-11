package checks

import (
	"path/filepath"
	"sync"
	"time"
)

// RemovedFile is content a file response took away from a path: the bytes a
// quarantine moved out or a clean replaced.
type RemovedFile struct {
	Path   string
	SHA256 string
	Size   int64
	At     time.Time
	// Action is "quarantine" or "clean".
	Action string
	Seq    uint64
}

// removedFileMemory is how long a removal stays recognisable. A restore loop
// can outwait an operator for days; entries are small and their number is
// bounded by the file response budget and by operator actions.
const removedFileMemory = 7 * 24 * time.Hour

var removedFilesNow = time.Now

// removedFiles lives in process memory, not in state: after a restart a file
// coming back is judged by content detection alone.
var removedFiles struct {
	sync.RWMutex
	byPath map[string]RemovedFile
	seq    uint64
}

func rememberRemovedFile(path, digest string, size int64, action string) {
	if path == "" || digest == "" {
		return
	}
	now := removedFilesNow()
	path = filepath.Clean(path)
	removedFiles.Lock()
	defer removedFiles.Unlock()
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
}
