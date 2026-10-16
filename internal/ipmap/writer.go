package ipmap

import (
	"errors"
	"fmt"
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
	Path  string
	chown func(path string, gid int) error

	mu    sync.Mutex
	last  Map
	state State
}

// NewWriter returns a writer for path.
func NewWriter(path string) *Writer {
	return &Writer{Path: path, chown: func(p string, gid int) error { return os.Chown(p, -1, gid) }}
}

// Write renders m and replaces the file when the content changed: a
// temporary file in the same directory, fsync, mode 0640, group gid, rename
// and a directory fsync. A failure keeps the previous file, which rspamd
// keeps using. gid is rspamd's group; without it the file would be
// unreadable to rspamd, so nothing is written.
func (w *Writer) Write(m Map, gid int, now time.Time) (bool, error) {
	content, gen := m.Render()
	w.mu.Lock()
	defer w.mu.Unlock()
	if gen == w.state.Gen && w.state.Err == nil {
		return false, nil
	}
	err := w.replace(content, gid)
	if err != nil {
		w.state.Err = err
		return false, err
	}
	w.last, w.state = m, State{Gen: gen, WrittenAt: now}
	return true, nil
}

func (w *Writer) replace(content []byte, gid int) error {
	if gid < 0 {
		return errors.New("rspamd's group is unknown")
	}
	dir := filepath.Dir(w.Path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(w.Path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err = tmp.Write(content); err == nil {
		err = tmp.Sync()
	}
	if err == nil {
		err = tmp.Chmod(0o640)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = w.chown(name, gid)
	}
	if err == nil {
		err = os.Rename(name, w.Path)
	}
	if err != nil {
		return fmt.Errorf("writing %s: %w", w.Path, err)
	}
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
	return nil
}
