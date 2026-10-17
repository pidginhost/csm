package ipmap

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// State is what the writer last did.
type State struct {
	Gen       string
	WrittenAt time.Time
	Err       error
}

// Writer writes the map when its content changes and keeps the last written
// map as the lookup spam evidence subtracts (spec 7.2).
type Writer struct {
	Path    string
	chown   func(path string, gid int) error
	syncDir func(path string) error

	mu    sync.Mutex
	last  Map
	state State
	file  os.FileInfo
	gid   int
}

// NewWriter returns a writer for path.
func NewWriter(path string) *Writer {
	return &Writer{Path: path, chown: func(p string, gid int) error { return os.Chown(p, -1, gid) }, syncDir: syncDirectory}
}

// Write replaces the map when its content, service group or file metadata no
// longer match what it last wrote, or the file is missing. Failures before
// rename keep the previous file and lookup. After rename, wrote is true and
// the lookup follows the published file even if syncing the directory fails;
// err then reports uncertain durability. gid is rspamd's group; without it
// the file would be unreadable to rspamd.
func (w *Writer) Write(m Map, gid int, now time.Time) (bool, error) {
	content, gen := m.Render()
	w.mu.Lock()
	defer w.mu.Unlock()
	if gid < 0 {
		w.state.Err = errors.New("rspamd's group is unknown")
		return false, w.state.Err
	}
	if gen == w.state.Gen && gid == w.gid && w.state.Err == nil && w.file != nil {
		// Content alone does not prove the map is still present and readable
		// after a package change or an operator replacing the file.
		if info, err := os.Lstat(w.Path); err == nil && os.SameFile(info, w.file) &&
			info.Mode() == w.file.Mode() && info.Size() == w.file.Size() && info.ModTime().Equal(w.file.ModTime()) {
			return false, nil
		}
	}
	wrote, err := w.replace(content, gid)
	if wrote {
		w.last, w.state, w.gid = m, State{Gen: gen, WrittenAt: now}, gid
		// A lost stat only disables the no-op check on the next write.
		w.file, _ = os.Lstat(w.Path)
	}
	w.state.Err = err
	return wrote, err
}

func (w *Writer) replace(content []byte, gid int) (bool, error) {
	dir := filepath.Dir(w.Path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(w.Path)+".*")
	if err != nil {
		return false, w.writeErr(err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err = tmp.Write(content); err == nil {
		err = tmp.Chmod(0o640)
	}
	if err == nil {
		err = w.chown(name, gid)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(name, w.Path)
	}
	if err != nil {
		return false, w.writeErr(err)
	}
	if err := w.syncDir(dir); err != nil {
		return true, fmt.Errorf("syncing %s: %w", dir, err)
	}
	return true, nil
}

// writeErr names the map in err instead of the random temporary file, so a
// persistent failure reads the same on every attempt.
func (w *Writer) writeErr(err error) error {
	var pe *fs.PathError
	var le *os.LinkError
	switch {
	case errors.As(err, &pe):
		err = fmt.Errorf("%s: %w", pe.Op, pe.Err)
	case errors.As(err, &le):
		err = fmt.Errorf("%s: %w", le.Op, le.Err)
	}
	return fmt.Errorf("writing %s: %w", w.Path, err)
}

func syncDirectory(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the map's own directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// Weight looks a up in the last written map, in tenths.
func (w *Writer) Weight(a netip.Addr) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.last.Weight(a)
}

// State reports the last write.
func (w *Writer) State() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state
}

// Remove deletes the map and forgets it; a missing file is fine.
func (w *Writer) Remove() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := os.Remove(w.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	w.last, w.state = Map{}, State{}
	w.file = nil
	return nil
}
