package txn

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/safepath"
)

// restoredCopy retains the source directory and snapshot through completion
// and rollback. A pathname alone cannot identify the copy after a rename.
type restoredCopy struct {
	path     string
	target   *safepath.Target
	saved    fileState
	consumed bool
}

// restoreCopies substitutes the operator's newest backup for each selected
// deletion. A matching unsafe backup must fail the transaction, not silently
// turn a restore into a deletion or select an older backup.
func (t *tx) restoreCopies(changes []change, want func(path string) bool) error {
	selected := func(c change) bool { return !c.next.exists && c.target.Kind.WholeFile() && want(c.target.Path) }
	if !slices.ContainsFunc(changes, selected) {
		return nil
	}
	path := t.h.path(antispam.ReplacedDir)
	dir, err := safepath.OpenDirNoFollow(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	info, err := dir.Info()
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != os.Geteuid() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("operator backup directory is not private and worker-owned")
	}
	entries, err := dir.ReadDir()
	if err != nil {
		return err
	}
	newest := map[string]string{}
	for _, e := range entries {
		if p, ok := antispam.ParseBackupName(e.Name()); ok {
			newest[p] = max(newest[p], e.Name())
		}
	}
	for i, c := range changes {
		name, ok := newest[c.target.Path]
		if !ok || !selected(c) {
			continue
		}
		// Deleting a loosened CSM file is safe, but restoring private
		// operator content needs metadata we can trust. Its original
		// permissions cannot be recovered from the root-only backup.
		if usableErr := antispam.OptionalUsable(c.target); usableErr != nil {
			return usableErr
		}
		p := filepath.Join(path, name)
		target, err := safepath.OpenTarget("/", strings.TrimPrefix(p, "/"), false)
		if err != nil {
			return err
		}
		r := &restoredCopy{path: p, target: target}
		t.restored = append(t.restored, r)
		if same, compareErr := dir.SameFile(target.Parent); compareErr != nil || !same {
			return fmt.Errorf("operator backup directory %w", errConflict)
		}
		saved, err := readPinned(target.Parent, name)
		if err != nil {
			return err
		}
		if !saved.exists || saved.uid != os.Geteuid() || saved.perm != 0o600 {
			return errors.New("operator backup is not a private worker-owned regular file")
		}
		r.saved = saved
		// Keep only metadata checked before the restore. Refreshing it at
		// rename time could publish private operator content with a mode
		// another writer just loosened on CSM's file.
		next := fileState{exists: true, content: saved.content, metadata: true,
			uid: os.Geteuid(), gid: c.target.File.GID, perm: fileMode(c.target.File.Mode)}
		changes[i].next = next
	}
	return nil
}

// consume first moves the source to a private name, then checks the exact
// file it will delete. A changed copy goes back without replacing a new
// operator entry. All operations stay in the pinned backup directory.
func (r *restoredCopy) consume() error {
	if err := r.target.Check(); err != nil {
		return err
	}
	dir, name := r.target.Parent, r.target.Name
	held, heldName, err := dir.CreatePrivateTemp()
	if err != nil {
		return err
	}
	defer func() {
		_ = held.Close()
		_ = dir.RemoveDir(heldName)
	}()
	if err = dir.RenameTo(name, held, name); err != nil {
		return err
	}
	cur, err := readPinned(held, name)
	if err != nil || cur != r.saved {
		return errors.Join(errConflict, err, held.RenameTo(name, dir, name), syncPinned(dir))
	}
	if err := held.Remove(name); err != nil {
		return errors.Join(err, held.RenameTo(name, dir, name), syncPinned(dir))
	}
	r.consumed = true
	return errors.Join(syncPinned(held), syncPinned(dir))
}

func (t *tx) consumeRestored() error {
	for _, r := range t.restored {
		if err := r.consume(); err != nil {
			return err
		}
	}
	return t.fwd.Err()
}

func (t *tx) restoreConsumedCopies() error {
	var errs []error
	for _, r := range t.restored {
		if !r.consumed {
			continue
		}
		if err := replacePinned(r.target, fileState{}, r.saved); err != nil {
			errs = append(errs, fmt.Errorf("restoring backup %s: %w", strings.TrimPrefix(r.path, t.h.root), err))
			continue
		}
		r.consumed = false
		if err := r.target.Check(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
