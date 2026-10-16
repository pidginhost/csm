package antispam

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
)

// OptionalUsable reports why CSM cannot write optional target t, or nil:
// its directory must exist, every parent and the file must be protected
// root-owned objects, and an existing file must be CSM's. The daemon leaves
// out the feed or redirect that needs t; the worker refuses to write it.
func OptionalUsable(t TargetFacts) error {
	if t.Err != nil {
		if errors.Is(t.Err, fs.ErrNotExist) {
			return fmt.Errorf("the directory %s is missing", path.Dir(t.Path))
		}
		return fmt.Errorf("cannot check %s; check file access", t.Path)
	}
	if len(t.Parents) == 0 {
		return fmt.Errorf("the parent directories of %s were not checked", t.Path)
	}
	for _, p := range t.Parents {
		if !p.Mode.IsDir() {
			return fmt.Errorf("%s is not a directory", p.Path)
		}
		if problem := unprotected(p); problem != "" {
			return fmt.Errorf("%s %s", p.Path, problem)
		}
	}
	if t.Missing {
		return nil
	}
	if !t.File.Mode.IsRegular() {
		return fmt.Errorf("%s is not a regular file", t.Path)
	}
	if problem := unprotected(t.File); problem != "" {
		return fmt.Errorf("%s %s", t.Path, problem)
	}
	if !IsManaged(t.Content) {
		return fmt.Errorf("%s is not managed by CSM", t.Path)
	}
	return nil
}

// SecretFileMode is the mode of override.d/rbl.conf while it holds the DQS
// key: rspamd reads it through its group, nobody else can.
const SecretFileMode fs.FileMode = 0o640

// secretFileOK reports whether override.d/rbl.conf is root-owned, in
// rspamd's group and mode SecretFileMode.
func secretFileOK(f HostFacts) bool {
	for _, t := range f.Targets {
		if t.Path == FeedRBLPath {
			return t.Err == nil && !t.Missing && t.File.UID == 0 && f.RspamdGID >= 0 &&
				t.File.GID == f.RspamdGID && t.File.Mode.Perm() == SecretFileMode
		}
	}
	return false
}
