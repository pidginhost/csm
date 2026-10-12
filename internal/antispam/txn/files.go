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
	st := fileState{exists: true, content: string(data), uid: -1, gid: -1, perm: info.Mode().Perm()}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		st.uid, st.gid = int(sys.Uid), int(sys.Gid)
	}
	return st, nil
}

// errConflict marks a file someone else changed during the transaction. It
// is never overwritten from a stale snapshot (spec section 6.3 step 1).
var errConflict = errors.New("changed by another writer during the transaction")

// replaceFile makes p hold next, provided p still holds want. An existing
// file keeps its owner and mode; a new one is 0644 and owned by the worker.
// next.exists false removes p.
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
	perm, uid, gid := fs.FileMode(0o644), -1, -1
	if cur.exists {
		perm, uid, gid = cur.perm, cur.uid, cur.gid
	}
	return writeAtomic(p, next.content, perm, uid, gid)
}

// writeAtomic writes p through a temporary file in its directory, fsyncs it,
// renames it into place and fsyncs the directory. uid -1 keeps the owner.
func writeAtomic(p, content string, perm fs.FileMode, uid, gid int) error {
	dir := filepath.Dir(p)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(p)+".*.csmtmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	done := false
	defer func() {
		if !done {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if uid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			return err
		}
	}
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := io.WriteString(tmp, content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, p); err != nil {
		return err
	}
	done = true
	return syncDir(dir)
}

// deleteFile removes CSM's own file p, if present, durably.
func deleteFile(p string) error {
	if err := os.Remove(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return syncDir(filepath.Dir(p))
}

func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- directory of a fixed target path
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// privateDir creates dir as a root-only directory, or checks an existing
// one is a real directory and narrows it to 0700.
func privateDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if info.Mode().Perm() != 0o700 {
		// #nosec G302 -- a directory needs its search bit; 0700 is root-only.
		return os.Chmod(dir, 0o700)
	}
	return nil
}
