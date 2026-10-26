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
		if f.Size > s.maxBytes-total {
			return fmt.Errorf("crash sample exceeds the %d byte cap", s.maxBytes)
		}
		total += f.Size
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	root, err := s.openDir(true)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if _, err = s.sweep(root); err != nil {
		return err
	}
	if _, err = root.Lstat(name); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = s.evict(root, total); err != nil {
		return err
	}
	tmp := tmpPrefix + name
	if err = root.Mkdir(tmp, 0o700); err != nil {
		return fmt.Errorf("crash sample: %w", err)
	}
	defer func() { _ = root.RemoveAll(tmp) }()
	staging, err := openChildRoot(root, tmp)
	if err != nil {
		return err
	}
	defer func() { _ = staging.Close() }()
	if err = s.write(staging, files); err != nil {
		return err
	}
	now := s.now()
	if err = staging.Chtimes(".", now, now); err != nil {
		return fmt.Errorf("crash sample: %w", err)
	}
	if err = sameDirectory(root, tmp, staging); err != nil {
		return err
	}
	if err = root.Rename(tmp, name); err != nil {
		return fmt.Errorf("crash sample: %w", err)
	}
	return nil
}

func (s *Store) write(staging *os.Root, files []File) error {
	for _, f := range files {
		out, err := staging.OpenFile(f.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return fmt.Errorf("crash sample: %w", err)
		}
		_, err = io.CopyN(out, io.NewSectionReader(f.Src, 0, f.Size), f.Size)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("crash sample %s: %w", f.Name, err)
		}
	}
	return nil
}

// Pin the store and staging directories for the whole operation. A path
// check alone would let a replacement link redirect later copies or cleanup.
func (s *Store) openDir(create bool) (*os.Root, error) {
	parent, err := openParent(s.dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = parent.Close() }()
	name := filepath.Base(s.dir)
	if create {
		if err = parent.Mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	root, err := openChildRoot(parent, name)
	if err != nil {
		return nil, err
	}
	// Chmod the pinned directory, not its replaceable pathname.
	dir, err := root.Open(".")
	if err == nil {
		err = dir.Chmod(0o700) // #nosec G302 -- directory needs owner search permission.
		_ = dir.Close()
	}
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

// openParent opens the directory that holds the store. That path belongs to
// root's layout and may contain links (such as /opt on a symlink); only the
// store directory itself is pinned against replacement.
func openParent(path string) (*os.Root, error) {
	abs, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	return os.OpenRoot(abs)
}

func openChildRoot(parent *os.Root, name string) (*os.Root, error) {
	info, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("crash sample: %q is not a directory", name)
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	pinned, err := root.Stat(".")
	if err != nil || !os.SameFile(info, pinned) {
		_ = root.Close()
		return nil, fmt.Errorf("crash sample: directory %q changed while opening", name)
	}
	return root, nil
}

func sameDirectory(parent *os.Root, name string, root *os.Root) error {
	info, err := parent.Lstat(name)
	if err != nil {
		return err
	}
	pinned, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !info.IsDir() || !os.SameFile(info, pinned) {
		return fmt.Errorf("crash sample: directory %q changed while saving", name)
	}
	return nil
}

// list returns the stored samples, oldest first, and removes leftover
// temporary directories.
func (s *Store) list(root *os.Root) ([]sample, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("crash sample: %w", err)
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var out []sample
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			if err := root.RemoveAll(e.Name()); err != nil {
				return nil, err
			}
			continue
		}
		info, err := root.Lstat(e.Name())
		if err != nil {
			return nil, err
		}
		smp := sample{name: e.Name(), mtime: info.ModTime()}
		if info.IsDir() {
			// Open one component with NOFOLLOW so even a concurrent link
			// replacement cannot make retention inspect another tree.
			dir, err := root.OpenFile(e.Name(), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				return nil, err
			}
			files, err := dir.Readdir(-1)
			_ = dir.Close()
			if err != nil {
				return nil, err
			}
			for _, fi := range files {
				smp.size += fi.Size()
			}
		}
		out = append(out, smp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].mtime.Before(out[j].mtime) })
	return out, nil
}

// evict removes the oldest samples until one more of size bytes fits.
func (s *Store) evict(root *os.Root, size int64) error {
	stored, err := s.list(root)
	if err != nil {
		return err
	}
	var total int64
	for _, smp := range stored {
		total += smp.size
	}
	for len(stored) > 0 && (len(stored) >= MaxSamples || total+size > s.maxBytes) {
		if err := root.RemoveAll(stored[0].name); err != nil {
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
	root, err := s.openDir(false)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("crash sample: %w", err)
	}
	defer func() { _ = root.Close() }()
	return s.sweep(root)
}

func (s *Store) sweep(root *os.Root) (int, error) {
	stored, err := s.list(root)
	if err != nil {
		return 0, err
	}
	cutoff := s.now().Add(-MaxAge)
	removed := 0
	for _, smp := range stored {
		if !smp.mtime.Before(cutoff) {
			break
		}
		if err := root.RemoveAll(smp.name); err != nil {
			return removed, fmt.Errorf("crash sample: %w", err)
		}
		removed++
	}
	return removed, nil
}
