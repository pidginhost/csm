package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
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

	path string
	lock *os.File
}

var registeredName = regexp.MustCompile(`^(?:dom-[0-9a-f]{6}\.example|acct-[0-9a-f]{6}|e-[0-9a-f]{16})$`)

// openRegistry locks the registry against concurrent conversions and reads
// it, creating an empty one for a salt used for the first time.
func openRegistry(path, fingerprint string) (*identityRegistry, error) {
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- operator-chosen registry path; symlinks refused
	if err != nil {
		return nil, errRegistry
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errRegistry
	}
	r := &identityRegistry{FormatVersion: 1, SaltFingerprint: fingerprint, Names: map[string]string{}, path: path, lock: lock}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- operator-chosen registry path; symlinks refused
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		r.close()
		return nil, errRegistry
	}
	info, statErr := f.Stat()
	b, readErr := io.ReadAll(f)
	closeErr := f.Close()
	var stored identityRegistry
	switch {
	case statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0, readErr != nil, closeErr != nil,
		crawlreplay.DecodeStrictJSON(b, &stored) != nil, stored.FormatVersion != 1, stored.SaltFingerprint != fingerprint, stored.Names == nil:
		r.close()
		return nil, errRegistry
	}
	for name, digest := range stored.Names {
		if !registeredName.MatchString(name) || !lowerHex64.MatchString(digest) {
			r.close()
			return nil, errRegistry
		}
	}
	r.Names = stored.Names
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
	f, err := os.CreateTemp(filepath.Dir(r.path), ".domlog-stream-registry-*.tmp")
	if err != nil {
		return errRegistry
	}
	_, writeErr := f.Write(append(b, '\n'))
	if err = errors.Join(writeErr, f.Chmod(0o600), f.Sync(), f.Close()); err != nil {
		os.Remove(f.Name())
		return errRegistry
	}
	if err = os.Rename(f.Name(), r.path); err != nil {
		os.Remove(f.Name())
		return errRegistry
	}
	return nil
}

func (r *identityRegistry) close() { r.lock.Close() }
