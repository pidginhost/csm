// Package crashsample keeps private copies of inputs that crashed a parse
// worker, for diagnosis. The copies hold customer mail and tenant files, so
// the store is bounded in count, bytes and age, and readable by root only.
package crashsample

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// MaxSamples is how many samples the store keeps; the oldest go first.
	MaxSamples = 20
	// MaxBytes bounds the store's total size.
	MaxBytes = 500 << 20
	// MaxAge is how long a sample is kept.
	MaxAge = 7 * 24 * time.Hour

	tmpPrefix = ".tmp-"
)

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// File is one file of a sample, copied from Src without moving any shared
// file offset.
type File struct {
	Name string
	Src  io.ReaderAt
	Size int64
}

// Store keeps samples as directories under dir.
type Store struct {
	dir      string
	maxBytes int64
	now      func() time.Time
	mu       sync.Mutex
}

// New returns a store in dir, which is created on first save.
func New(dir string) *Store {
	return &Store{dir: dir, maxBytes: MaxBytes, now: time.Now}
}

type sample struct {
	name  string
	mtime time.Time
	size  int64
}

// Save stores files as sample name, evicting the oldest samples first so the
// store stays within MaxSamples and the byte cap. A sample that already
// exists is kept as it is.
func (s *Store) Save(name string, files []File) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("crash sample: invalid name %q", name)
	}
	var total int64
	for _, f := range files {
		if !validName.MatchString(f.Name) || f.Size < 0 {
			return fmt.Errorf("crash sample: invalid file %q", f.Name)
		}
		total += f.Size
	}
	if total > s.maxBytes {
		return fmt.Errorf("crash sample: %d bytes exceeds the %d byte cap", total, s.maxBytes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureDir(); err != nil {
		return err
	}
	final := filepath.Join(s.dir, name)
	if _, err := os.Lstat(final); err == nil {
		return nil
	}
	if err := s.evict(total); err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, tmpPrefix+name)
	if err := os.RemoveAll(tmp); err != nil {
		return fmt.Errorf("crash sample: %w", err)
	}
	if err := s.write(tmp, files); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	now := s.now()
	if err := os.Chtimes(tmp, now, now); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("crash sample: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("crash sample: %w", err)
	}
	return nil
}

func (s *Store) write(tmp string, files []File) error {
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return fmt.Errorf("crash sample: %w", err)
	}
	for _, f := range files {
		// #nosec G304 -- tmp is under the store directory and f.Name passed validName.
		out, err := os.OpenFile(filepath.Join(tmp, f.Name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return fmt.Errorf("crash sample: %w", err)
		}
		_, err = io.Copy(out, io.NewSectionReader(f.Src, 0, f.Size))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("crash sample %s: %w", f.Name, err)
		}
	}
	return nil
}

// ensureDir creates the store directory, or checks that it is a real
// directory: a link in its place is never followed.
func (s *Store) ensureDir() error {
	info, err := os.Lstat(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		if mkErr := os.Mkdir(s.dir, 0o700); mkErr != nil {
			return fmt.Errorf("crash sample: %w", mkErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("crash sample: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("crash sample: %s is not a directory", s.dir)
	}
	if info.Mode().Perm() != 0o700 {
		// #nosec G302 -- a directory; 0700 is the tightest usable mode.
		return os.Chmod(s.dir, 0o700)
	}
	return nil
}

// list returns the stored samples, oldest first, and removes leftover
// temporary directories.
func (s *Store) list() ([]sample, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("crash sample: %w", err)
	}
	var out []sample
	for _, e := range entries {
		path := filepath.Join(s.dir, e.Name())
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			_ = os.RemoveAll(path)
			continue
		}
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		smp := sample{name: e.Name(), mtime: info.ModTime()}
		if files, err := os.ReadDir(path); err == nil {
			for _, f := range files {
				if fi, err := f.Info(); err == nil {
					smp.size += fi.Size()
				}
			}
		}
		out = append(out, smp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].mtime.Before(out[j].mtime) })
	return out, nil
}

// evict removes the oldest samples until one more of size bytes fits.
func (s *Store) evict(size int64) error {
	stored, err := s.list()
	if err != nil {
		return err
	}
	var total int64
	for _, smp := range stored {
		total += smp.size
	}
	for len(stored) > 0 && (len(stored) >= MaxSamples || total+size > s.maxBytes) {
		if err := os.RemoveAll(filepath.Join(s.dir, stored[0].name)); err != nil {
			return fmt.Errorf("crash sample: %w", err)
		}
		total -= stored[0].size
		stored = stored[1:]
	}
	return nil
}

// Sweep removes samples older than MaxAge and leftover temporary
// directories, and reports how many samples it removed.
func (s *Store) Sweep() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := os.Lstat(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("crash sample: %w", err)
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("crash sample: %s is not a directory", s.dir)
	}
	stored, err := s.list()
	if err != nil {
		return 0, err
	}
	cutoff := s.now().Add(-MaxAge)
	removed := 0
	for _, smp := range stored {
		if !smp.mtime.Before(cutoff) {
			break
		}
		if err := os.RemoveAll(filepath.Join(s.dir, smp.name)); err != nil {
			return removed, fmt.Errorf("crash sample: %w", err)
		}
		removed++
	}
	return removed, nil
}
