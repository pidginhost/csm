package learnwatch

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/antispam/learn"
	"github.com/pidginhost/csm/internal/safepath"
)

// Folders are the observed folders of every mailbox (spec 7.1): .spam is
// Dovecot's Junk special-use folder, .Junk the folder cPanel creates.
var Folders = []string{".spam", ".Junk"}

// Subdirs are the Maildir subdirectories read; IMAP moves land in cur.
var Subdirs = []string{"new", "cur"}

// ErrUnsafePath: a mail path component is a symlink, not a directory, or
// a name CSM does not traverse. The layout is reported, never followed.
var ErrUnsafePath = errors.New("mail path is not a plain directory tree")

var errHomeOwner = errors.New("home directory is not owned by the account")

// Mailbox is the main mailbox (both empty) or Box@Domain.
type Mailbox struct {
	Domain, Box string
}

// Meta is descriptor metadata compared before and after a read.
type Meta struct {
	Dev, Ino uint64
	UID      int
	Nlink    uint64
	Size     int64
	MtimeNs  int64
	CtimeNs  int64
}

// ReadStatus says what a message read found. Pending statuses retry next
// pass; skip statuses are terminal; ReadGone is not a report.
type ReadStatus int

// Read statuses.
const (
	ReadOK ReadStatus = iota
	ReadPendingLinked
	ReadPendingChanged
	ReadGone
	ReadSkipNotRegular
	ReadSkipWrongOwner
	ReadSkipOversize
	ReadSkipSymlink
)

var readStatusNames = [...]string{"ok", "linked", "changed", "gone", "not_regular", "wrong_owner", "oversize", "symlink"}

func (s ReadStatus) String() string {
	if s >= 0 && int(s) < len(readStatusNames) {
		return readStatusNames[s]
	}
	return fmt.Sprintf("status(%d)", int(s))
}

// afterRead runs between the read and the second fstat; tests inject
// writers here.
var afterRead = func() {}

// Home is an account's home directory, pinned without following links and
// owned by the account.
type Home struct {
	dir  *safepath.Dir
	path string
	uid  int
}

// OpenHome pins a's home from the filesystem root and checks its owner.
func OpenHome(a Account) (*Home, error) {
	d, err := safepath.OpenDirNoFollow(a.Home)
	if err != nil {
		return nil, err
	}
	fi, err := d.Info()
	if err == nil {
		if m, ok := metaOf(fi); !ok || m.UID != a.UID {
			err = errHomeOwner
		}
	}
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	return &Home{dir: d, path: filepath.Clean(a.Home), uid: a.UID}, nil
}

// Close releases the home descriptor.
func (h *Home) Close() error { return h.dir.Close() }

// plainName is one directory component CSM may traverse.
func plainName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00")
}

func mailboxPath(m Mailbox, folder, sub string) (string, error) {
	if !slices.Contains(Folders, folder) || !slices.Contains(Subdirs, sub) {
		return "", fmt.Errorf("%w: folder %q/%q is not observed", ErrUnsafePath, folder, sub)
	}
	switch {
	case m == Mailbox{}:
		return "mail", nil
	case ValidDomain(m.Domain) && ValidMailbox(m.Box):
		return "mail/" + m.Domain + "/" + m.Box, nil
	}
	return "", fmt.Errorf("%w: unsupported mailbox name", ErrUnsafePath)
}

// siblingFolder accepts a folder link that names another unobserved Maildir++
// folder of the same mailbox, as ".name" or as that exact absolute path. Some
// older cPanel accounts keep .spam as such a link; nothing else is followed.
func siblingFolder(target, mailboxAbs string) (string, bool) {
	name := target
	if strings.HasPrefix(target, "/") {
		name = strings.TrimPrefix(target, mailboxAbs+"/")
		if name == target {
			return "", false
		}
	}
	return name, plainName(name) && strings.HasPrefix(name, ".") && name != ".." && !slices.Contains(Folders, name)
}

// OpenFolder opens one observed Maildir subdirectory beneath the home, one
// no-follow component at a time. A missing folder wraps fs.ErrNotExist;
// symlinks and non-directories wrap ErrUnsafePath, except a folder linked to
// a sibling folder (siblingFolder). Other errors are retryable.
func (h *Home) OpenFolder(m Mailbox, folder, sub string) (*Folder, error) {
	rel, err := mailboxPath(m, folder, sub)
	if err != nil {
		return nil, err
	}
	d, err := h.dir.Walk(rel + "/" + folder + "/" + sub)
	if errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) {
		d, err = h.openSibling(rel, folder, sub, err)
	}
	if err != nil {
		if errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: %w", ErrUnsafePath, err)
		}
		return nil, err
	}
	fi, err := d.Info()
	var ident Meta
	if err == nil {
		var ok bool
		if ident, ok = metaOf(fi); !ok {
			err = errors.ErrUnsupported
		}
	}
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	return &Folder{dir: d, ident: ident}, nil
}

// openSibling preserves the original unsafe-path error only when the folder
// is not a permitted link. Lookup failures must keep their retry semantics.
func (h *Home) openSibling(rel, folder, sub string, cause error) (*safepath.Dir, error) {
	mbox, err := h.dir.Walk(rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = mbox.Close() }()
	target, err := mbox.Readlink(folder)
	if errors.Is(err, syscall.EINVAL) {
		return nil, cause
	}
	if err != nil {
		return nil, err
	}
	name, ok := siblingFolder(target, h.path+"/"+rel)
	if !ok {
		return nil, cause
	}
	return mbox.Walk(name + "/" + sub)
}

// Folder is an open Maildir subdirectory.
type Folder struct {
	dir   *safepath.Dir
	ident Meta
}

// Close releases the folder descriptor.
func (f *Folder) Close() error { return f.dir.Close() }

// Identity is the folder's device, inode and timestamps when it was opened.
func (f *Folder) Identity() (dev, ino uint64, mtimeNs, ctimeNs int64) {
	return f.ident.Dev, f.ident.Ino, f.ident.MtimeNs, f.ident.CtimeNs
}

// Next returns at most n entry names; io.EOF follows the last batch.
func (f *Folder) Next(n int) ([]string, error) {
	entries, err := f.dir.ReadDirN(n)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, err
}

// Stat reads an entry's metadata without opening it. A non-nil error is
// transient and its status is meaningless.
func (f *Folder) Stat(name string) (Meta, ReadStatus, error) {
	fi, err := lstatAt(f.dir, name)
	if errors.Is(err, fs.ErrNotExist) {
		return Meta{}, ReadGone, nil
	}
	if err != nil {
		return Meta{}, ReadOK, err
	}
	m, ok := metaOf(fi)
	switch {
	case !ok:
		return Meta{}, ReadOK, errors.ErrUnsupported
	case fi.Mode()&fs.ModeSymlink != 0:
		return m, ReadSkipSymlink, nil
	case !fi.Mode().IsRegular():
		return m, ReadSkipNotRegular, nil
	}
	return m, ReadOK, nil
}

// classify applies the per-file rules of spec 7.1 to descriptor metadata.
func classify(fi os.FileInfo, m Meta, uid int) ReadStatus {
	switch {
	case !fi.Mode().IsRegular():
		return ReadSkipNotRegular
	case m.UID != uid:
		return ReadSkipWrongOwner
	case m.Nlink == 0:
		return ReadGone
	case m.Size > learn.MaxBody:
		return ReadSkipOversize
	case m.Nlink > 1:
		return ReadPendingLinked
	}
	return ReadOK
}

// ReadMessage takes a bounded snapshot of one message owned by uid. The
// snapshot is returned only with ReadOK or ReadPendingLinked, when the
// descriptor metadata did not change across the read; a link elsewhere does
// not change the content, only when it may be reported. A non-nil error is
// transient; retry later.
func (f *Folder) ReadMessage(name string, uid int) ([]byte, Meta, ReadStatus, error) {
	named, status, err := f.Stat(name)
	if err != nil || status != ReadOK {
		return nil, named, status, err
	}
	file, err := f.dir.OpenFile(name, os.O_RDONLY|syscall.O_NOCTTY, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, Meta{}, ReadGone, nil
	case errors.Is(err, syscall.ELOOP):
		return nil, Meta{}, ReadSkipSymlink, nil
	case errors.Is(err, syscall.ENXIO):
		return nil, Meta{}, ReadSkipNotRegular, nil
	case err != nil:
		return nil, Meta{}, ReadOK, err
	}
	defer file.Close()
	before, status, err := fstatMeta(file, uid)
	if err != nil || status != ReadOK && status != ReadPendingLinked {
		return nil, before, status, err
	}
	if before.Dev != named.Dev || before.Ino != named.Ino {
		return nil, before, ReadPendingChanged, nil
	}
	data, err := io.ReadAll(io.LimitReader(file, learn.MaxBody+1))
	if err != nil {
		return nil, before, ReadOK, err
	}
	afterRead()
	after, status, err := fstatMeta(file, uid)
	switch {
	case err != nil:
		return nil, before, ReadOK, err
	case status == ReadGone:
		return nil, after, ReadGone, nil
	case after != before || int64(len(data)) != before.Size:
		return nil, after, ReadPendingChanged, nil
	case len(data) > learn.MaxBody:
		return nil, after, ReadSkipOversize, nil
	}
	// after equals before, so status is still OK or linked.
	return data, before, status, nil
}

func fstatMeta(file *os.File, uid int) (Meta, ReadStatus, error) {
	fi, err := file.Stat()
	if err != nil {
		return Meta{}, ReadOK, err
	}
	m, ok := metaOf(fi)
	if !ok {
		return Meta{}, ReadOK, errors.ErrUnsupported
	}
	return m, classify(fi, m, uid), nil
}

// BaseName is the folder-scoped Maildir identity: the name before the
// ":2," info suffix, which flag renames and new-to-cur moves keep.
func BaseName(name string) (string, bool) {
	if !plainName(name) {
		return "", false
	}
	base, _, _ := strings.Cut(name, ":2,")
	if !plainName(base) {
		return "", false
	}
	return base, true
}
