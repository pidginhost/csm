package learn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/safepath"
)

// DefaultBodiesDir holds one anchor body per cluster (spec 7.4).
const DefaultBodiesDir = antispam.DefaultLearningDir + "/anchors"

const stagePrefix = ".stage-"

// ErrBodyInvalid: an anchor body is missing, unsafe or no longer the bytes
// its cluster recorded. Publication of that cluster stops.
var ErrBodyInvalid = errors.New("anchor body is missing or changed")

// Bodies stores immutable anchor bodies: stored mail, root-only, never
// logged. Errors never carry content or paths.
type Bodies struct {
	Dir string
	// owner is the uid that must own the directory and files: root, except
	// in tests.
	owner int
	// writeFile writes and syncs a staged body; tests inject failures.
	writeFile func(*os.File, []byte) error
}

// Staged is a body written under a staging name, not yet committed.
type Staged struct {
	Name string
	Len  int64
	SHA  string
}

// BodyName is the committed file name of a cluster's anchor body.
func BodyName(clusterID uint64) string {
	return strconv.FormatUint(clusterID, 10) + ".msg"
}

// Keep the checked directory open so cleanup, rename and sync cannot be
// redirected by a replacement of its path.
func (b *Bodies) dir() (*safepath.Dir, error) {
	if err := os.MkdirAll(b.Dir, 0o700); err != nil {
		return nil, errors.New("cannot create the anchor body directory")
	}
	// A trailing slash makes Lstat follow a directory symlink.
	path := filepath.Clean(b.Dir)
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || ownerOf(info) != b.owner {
		return nil, errors.New("anchor body directory is not private to CSM")
	}
	dir, err := safepath.OpenDir(path)
	if err != nil {
		return nil, errors.New("cannot open the anchor body directory")
	}
	current, err := dir.Info()
	if err != nil || !os.SameFile(info, current) || current.Mode().Perm() != 0o700 || ownerOf(current) != b.owner {
		_ = dir.Close()
		return nil, errors.New("anchor body directory changed while opening")
	}
	return dir, nil
}

func ownerOf(info os.FileInfo) int {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

// Stage writes body under a fresh exclusive staging name, 0600, and syncs
// it. On any failure no file is left and no Staged is returned.
func (b *Bodies) Stage(body []byte) (Staged, error) {
	if len(body) > MaxBody {
		return Staged{}, errors.New("anchor body is larger than the learning limit")
	}
	dir, err := b.dir()
	if err != nil {
		return Staged{}, err
	}
	defer func() { _ = dir.Close() }()
	name := stagePrefix + rand.Text()
	f, err := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Staged{}, fmt.Errorf("cannot stage an anchor body: %w", unwrapErrno(err))
	}
	write := b.writeFile
	if write == nil {
		write = writeSync
	}
	// The process umask may remove owner permissions at creation.
	err = f.Chmod(0o600)
	if err == nil {
		err = write(f, body)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		stageErr := fmt.Errorf("cannot stage an anchor body: %w", unwrapErrno(err))
		if removeErr := dir.Remove(name); removeErr != nil {
			return Staged{}, errors.Join(stageErr, fmt.Errorf("cannot remove a staged anchor body: %w", unwrapErrno(removeErr)))
		}
		return Staged{}, errors.Join(stageErr, syncDir(dir))
	}
	sum := sha256.Sum256(body)
	return Staged{Name: name, Len: int64(len(body)), SHA: hex.EncodeToString(sum[:])}, nil
}

func writeSync(f *os.File, body []byte) error {
	if _, err := f.Write(body); err != nil {
		return err
	}
	return f.Sync()
}

// unwrapErrno keeps the errno (ENOSPC, EIO) and drops paths.
func unwrapErrno(err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	return errors.New("file system error")
}

// Commit gives a staged body its cluster's name and syncs the directory.
// It never replaces an existing body.
func (b *Bodies) Commit(s Staged, clusterID uint64) error {
	if !isStagedName(s.Name) {
		return errors.New("not a staged anchor body")
	}
	dir, err := b.dir()
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	if err := dir.RenameTo(s.Name, dir, BodyName(clusterID)); err != nil {
		return fmt.Errorf("cannot commit an anchor body: %w", unwrapErrno(err))
	}
	return syncDir(dir)
}

// Read returns a cluster's body after checking it is a private regular
// file of exactly the recorded length and SHA-256.
func (b *Bodies) Read(clusterID uint64, wantLen int64, wantSHA string) ([]byte, error) {
	dir, err := b.dir()
	if err != nil {
		return nil, ErrBodyInvalid
	}
	defer func() { _ = dir.Close() }()
	if wantLen < 0 || wantLen > MaxBody {
		return nil, ErrBodyInvalid
	}
	f, err := dir.OpenFile(BodyName(clusterID), os.O_RDONLY, 0)
	if err != nil {
		return nil, ErrBodyInvalid
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || ownerOf(info) != b.owner || info.Size() != wantLen {
		return nil, ErrBodyInvalid
	}
	body, err := io.ReadAll(io.LimitReader(f, wantLen+1))
	sum := sha256.Sum256(body)
	if err != nil || int64(len(body)) != wantLen || hex.EncodeToString(sum[:]) != wantSHA {
		return nil, ErrBodyInvalid
	}
	return body, nil
}

// Remove unlinks a cluster's body and syncs the directory. A missing body
// is already removed.
func (b *Bodies) Remove(clusterID uint64) error {
	dir, err := b.dir()
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Remove(BodyName(clusterID)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove an anchor body: %w", unwrapErrno(err))
	}
	return syncDir(dir)
}

// Orphans lists staged and committed bodies that referenced does not claim.
// Callers remove them only after ledger recovery.
func (b *Bodies) Orphans(referenced func(name string) bool) ([]string, error) {
	dir, err := b.dir()
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir()
	if err != nil {
		return nil, errors.New("cannot list anchor bodies")
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && isBodyName(name) && !referenced(name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out, nil
}

// RemoveOrphan unlinks one name Orphans returned.
func (b *Bodies) RemoveOrphan(name string) error {
	if !isBodyName(name) {
		return errors.New("not an anchor body name")
	}
	dir, err := b.dir()
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Remove(name); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove an anchor body: %w", unwrapErrno(err))
	}
	return syncDir(dir)
}

func isStagedName(name string) bool {
	return strings.HasPrefix(name, stagePrefix) && len(name) > len(stagePrefix) &&
		filepath.Base(name) == name && !strings.ContainsRune(name, '\x00')
}

func isBodyName(name string) bool {
	if isStagedName(name) {
		return true
	}
	id, ok := strings.CutSuffix(name, ".msg")
	n, err := strconv.ParseUint(id, 10, 64)
	return ok && err == nil && BodyName(n) == name
}

func syncDir(dir *safepath.Dir) error {
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("cannot sync the anchor directory: %w", unwrapErrno(err))
	}
	return nil
}
