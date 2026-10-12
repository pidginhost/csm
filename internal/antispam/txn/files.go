// Package txn runs CSM's antispam apply and remove transactions on a cPanel
// host (spec sections 6.3 and 6.4). It runs as root in the antispam worker,
// under the shared Exim mutation lock and outside the daemon's sandbox.
package txn

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/pidginhost/csm/internal/safepath"
)

// maxFileBytes bounds every file a transaction reads; cPanel's generated
// exim.conf is under 100 KiB.
const maxFileBytes = 16 << 20

// fileState is one file as a transaction saw it.
type fileState struct {
	exists   bool
	content  string
	uid, gid int
	perm     fs.FileMode
}

// sameContent reports whether two states hold the same bytes, or are both
// absent. Owner and mode changes are not content edits.
func sameContent(a, b fileState) bool {
	return a.exists == b.exists && a.content == b.content
}

// readFile reads p without following a final symbolic link or blocking on a
// FIFO. The caller has checked p's parent directories (spec 6.2 item 9).
func readFile(p string) (fileState, error) {
	// #nosec G304 -- fixed cPanel, rspamd and CSM paths from antispam.MutationTargets and the record path.
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return fileState{}, nil
	}
	if err != nil {
		return fileState{}, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return fileState{}, err
	}
	if !info.Mode().IsRegular() {
		return fileState{}, fmt.Errorf("%s is not a regular file", p)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return fileState{}, err
	}
	if len(data) > maxFileBytes {
		return fileState{}, fmt.Errorf("%s is larger than %d bytes", p, maxFileBytes)
	}
	st := fileState{exists: true, content: string(data), uid: -1, gid: -1, perm: fileMode(info.Mode())}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		st.uid, st.gid = int(sys.Uid), int(sys.Gid)
	}
	return st, nil
}

func fileMode(mode fs.FileMode) fs.FileMode {
	return mode & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
}

// errConflict marks a file someone else changed during the transaction. It
// is never overwritten from a stale snapshot (spec section 6.3 step 1).
var errConflict = errors.New("changed by another writer during the transaction")

// errDurability means the edit reached the destination but was not fsynced.
var errDurability = errors.New("file changed but directory sync failed")

// replaceFile makes p hold next, provided p still holds want. An existing
// file keeps its owner and mode; a new one is 0644 and owned by the worker.
// The completion record uses next.perm to stay private. next.exists false
// removes p.
func replaceFile(p string, want, next fileState) error {
	cur, err := readFile(p)
	if err != nil {
		return err
	}
	if !sameContent(cur, want) {
		return fmt.Errorf("%s %w", p, errConflict)
	}
	if !next.exists {
		return deleteFile(p)
	}
	tmp, err := stageFile(p, next.content)
	if err != nil {
		return err
	}
	defer discardTemp(tmp)
	return replaceStagedFile(p, want, tmp, next.perm)
}

// Staging and syncing may take long enough for another writer to change p.
// Recheck its content and refresh its metadata before publishing.
func replaceStagedFile(p string, want fileState, tmp *os.File, mode fs.FileMode) error {
	cur, err := readFile(p)
	if err != nil {
		return err
	}
	if !sameContent(cur, want) {
		return fmt.Errorf("%s %w", p, errConflict)
	}
	perm, uid, gid := fs.FileMode(0o644), -1, -1
	if cur.exists {
		perm, uid, gid = cur.perm, cur.uid, cur.gid
	}
	if mode != 0 {
		perm = mode
	}
	return publishFile(p, tmp, perm, uid, gid, cur.exists)
}

// writeAtomic writes p through a temporary file in its directory, fsyncs it,
// renames it into place and fsyncs the directory. IDs of -1 keep the worker's
// ownership of the temporary file.
func writeAtomic(p, content string, perm fs.FileMode, uid, gid int) error {
	tmp, err := stageFile(p, content)
	if err != nil {
		return err
	}
	defer discardTemp(tmp)
	return publishFile(p, tmp, perm, uid, gid, true)
}

func discardTemp(tmp *os.File) {
	_ = tmp.Close()
	_ = os.Remove(tmp.Name())
}

func stageFile(p, content string) (*os.File, error) {
	if len(content) > maxFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, maxFileBytes)
	}
	dir := filepath.Dir(p)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(p)+".*.csmtmp")
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(tmp, content); err != nil {
		discardTemp(tmp)
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		discardTemp(tmp)
		return nil, err
	}
	return tmp, nil
}

func publishFile(p string, tmp *os.File, perm fs.FileMode, uid, gid int, replace bool) error {
	if uid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			return err
		}
	}
	// Writing and chown can clear set-id bits, so set the final mode last.
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if replace {
		if err := os.Rename(tmp.Name(), p); err != nil {
			return err
		}
	} else {
		// Linking publishes a new file atomically without overwriting a
		// destination created after the content check.
		if err := os.Link(tmp.Name(), p); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("%s %w", p, errConflict)
			}
			return err
		}
		if err := os.Remove(tmp.Name()); err != nil {
			return err
		}
	}
	if err := syncDir(filepath.Dir(p)); err != nil {
		return fmt.Errorf("%w: %w", errDurability, err)
	}
	return nil
}

// deleteFile removes CSM's own file p, if present, durably.
func deleteFile(p string) error {
	if err := os.Remove(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := syncDir(filepath.Dir(p)); err != nil {
		return fmt.Errorf("%w: %w", errDurability, err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- directory of a fixed target path
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// privateDir requires worker ownership; the worker runs as root. Ancestors
// must be real directories, and chmod uses the opened directory's inode.
func privateDir(dir string) error {
	return privateDirOwned(dir, os.Geteuid())
}

func privateDirOwned(dir string, uid int) error {
	parent, err := safepath.OpenDirNoFollow(filepath.Dir(dir))
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	if mkdirErr := os.Mkdir(dir, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, fs.ErrExist) {
		return mkdirErr
	}
	d, err := parent.OpenFile(filepath.Base(dir), os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	info, err := d.Stat()
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != uid {
		return fmt.Errorf("%s is not owned by the worker", dir)
	}
	if fileMode(info.Mode()) != 0o700 {
		// #nosec G302 -- a directory needs its search bit; 0700 is root-only.
		if err := d.Chmod(0o700); err != nil {
			return err
		}
	}
	if err := d.Sync(); err != nil {
		return err
	}
	// Sync the entry as well as the directory, including a concurrent
	// creator's entry that might not yet be durable.
	return parent.Sync()
}
