package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

// identityRegistry is the private record of every site, account and episode
// pseudonym issued under one salt, across all of its bundles, with the full
// digest each is a prefix of. A later bundle whose different name takes an
// issued pseudonym is refused, so bundles sharing a salt never merge two
// identities. It holds keyed digests, never names.
type identityRegistry struct {
	FormatVersion   int               `json:"format_version"`
	SaltFingerprint string            `json:"salt_fingerprint"`
	Names           map[string]string `json:"names"`

	fs      fileSystem
	path    string
	lock    file
	syncDir func(string) error
	existed bool
}

var registeredName = regexp.MustCompile(`^(?:dom-[0-9a-f]{6}\.example|acct-[0-9a-f]{6}|e-[0-9a-f]{16})$`)

// The salt bytes determine the name, so another --registry filename or
// another name for the same salt cannot start a separate history or lock.
func registryPath(fsys fileSystem, saltPath, requested string, salt []byte) (string, error) {
	digest := sha256.Sum256(salt)
	name := "registry-" + hex.EncodeToString(digest[:]) + ".json"
	dir, err := registryParent(fsys, saltPath)
	if err != nil {
		return "", errRegistryPlace
	}
	if requested != "" {
		_, base := filepath.Split(requested)
		if base != name {
			return "", errRegistryPlace
		}
		other, err := registryParent(fsys, requested)
		if err != nil {
			return "", errRegistryPlace
		}
		saltDir, saltErr := fsys.Lstat(dir)
		registryDir, registryErr := fsys.Lstat(other)
		if saltErr != nil || registryErr != nil || !os.SameFile(saltDir, registryDir) {
			return "", errRegistryPlace
		}
	}
	return filepath.Join(dir, name), nil
}

func registryParent(fsys fileSystem, path string) (string, error) {
	// Split preserves symlink/.. traversal; Dir and Abs would clean it
	// before the filesystem can resolve which directory it actually names.
	dir, _ := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	dir, err := fsys.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	return filepath.Abs(dir)
}

// openRegistry locks the registry against concurrent conversions and reads
// it, creating an empty one for a salt used for the first time.
func openRegistry(fsys fileSystem, path, fingerprint string) (*identityRegistry, error) {
	lock, err := fsys.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, errRegistry
	}
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		lock.Close()
		return nil, errRegistry
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errRegistry
	}
	// A lock file replaced between the open and the flock leaves this run
	// holding a lock no other run can see; the path must still name it.
	current, err := fsys.Lstat(path + ".lock")
	if err != nil || !os.SameFile(info, current) {
		lock.Close()
		return nil, errRegistry
	}
	r := &identityRegistry{FormatVersion: 1, SaltFingerprint: fingerprint, Names: map[string]string{}, fs: fsys, path: path, lock: lock}
	r.syncDir = func(dir string) error { return syncDirectory(fsys, dir) }
	f, err := fsys.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		r.close()
		return nil, errRegistry
	}
	info, statErr := f.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		f.Close()
		r.close()
		return nil, errRegistry
	}
	b, readErr := io.ReadAll(f)
	closeErr := f.Close()
	var stored identityRegistry
	switch {
	case readErr != nil, closeErr != nil,
		crawlreplay.DecodeStrictJSON(b, &stored) != nil, stored.FormatVersion != 1, stored.SaltFingerprint != fingerprint, stored.Names == nil:
		r.close()
		return nil, errRegistry
	}
	for name, digest := range stored.Names {
		if !registeredName.MatchString(name) || !lowerHex64.MatchString(digest) {
			r.close()
			return nil, errRegistry
		}
		_, prefix, _ := strings.Cut(strings.TrimSuffix(name, ".example"), "-")
		if !strings.HasPrefix(digest, prefix) {
			r.close()
			return nil, errRegistry
		}
	}
	r.Names, r.existed = stored.Names, true
	return r, nil
}

// add records issued pseudonyms; a pseudonym already issued for a
// different digest is a collision between two names.
func (r *identityRegistry) add(named map[string]string) (changed bool, err error) {
	for name, digest := range named {
		old, ok := r.Names[name]
		if ok && old != digest {
			return false, errCollision
		}
		if !ok {
			r.Names[name] = digest
			changed = true
		}
	}
	return changed, nil
}

// save replaces the registry file atomically with a private copy.
func (r *identityRegistry) save() error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return errRegistry
	}
	f, err := r.fs.CreateTemp(filepath.Dir(r.path), ".domlog-stream-registry-*.tmp")
	if err != nil {
		return errRegistry
	}
	_, writeErr := f.Write(append(b, '\n'))
	if err = errors.Join(writeErr, f.Chmod(0o600), f.Sync(), f.Close()); err != nil {
		_ = r.fs.Remove(f.Name())
		return errRegistry
	}
	if err = r.fs.Rename(f.Name(), r.path); err != nil {
		_ = r.fs.Remove(f.Name())
		return errRegistry
	}
	// The rename must survive a crash before any dependent bundle can be
	// published. Syncing only the temporary file does not persist its name.
	if err = r.syncDir(filepath.Dir(r.path)); err != nil {
		return errRegistry
	}
	return nil
}

func (r *identityRegistry) close() { r.lock.Close() }

// syncDirectory persists a rename by syncing the directory that holds it.
func syncDirectory(fsys fileSystem, path string) error {
	dir, err := fsys.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
