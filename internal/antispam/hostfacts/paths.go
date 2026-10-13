// Package hostfacts reads the facts antispam.CheckHost evaluates. It only
// reads: files, lstat results, command output and one rspamd /ping.
package hostfacts

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/safepath"
)

// maxSymlinks matches the kernel's limit on links followed in one lookup.
const maxSymlinks = 40

// pathFacts is one lstat of p, with its extended ACL state.
func pathFacts(p string) (antispam.PathFacts, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return antispam.PathFacts{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return antispam.PathFacts{}, fmt.Errorf("%s: no ownership information", p)
	}
	acl := false
	if info.Mode()&fs.ModeSymlink == 0 {
		if acl, err = hasExtACL(p); err != nil {
			return antispam.PathFacts{}, fmt.Errorf("%s: %w", p, err)
		}
	}
	return antispam.PathFacts{Path: p, UID: int(st.Uid), GID: int(st.Gid), Mode: info.Mode(), ExtACL: acl}, nil
}

// chain lstats every directory from "/" down to dir without following
// symbolic links. It stops after an entry that is not a directory, which
// the checks reject.
func chain(dir string) ([]antispam.PathFacts, error) {
	paths := []string{"/"}
	for _, name := range names(dir) {
		paths = append(paths, filepath.Join(paths[len(paths)-1], name))
	}
	var out []antispam.PathFacts
	for _, p := range paths {
		facts, err := pathFacts(p)
		if err != nil {
			return out, err
		}
		out = append(out, facts)
		if !facts.Mode.IsDir() {
			break
		}
	}
	return out, nil
}

// resolve follows p the way connect(2) does. It returns the object p names
// and every directory a name was looked up in, in lookup order without
// repeats. A followed symlink's own directory is among them: whoever can
// write there can redirect the path.
func resolve(p string) (string, []string, error) {
	var dirs []string
	seen := make(map[string]bool)
	cur, rest, links := "/", lookupNames(p), 0
	for len(rest) > 0 {
		name := rest[0]
		rest = rest[1:]
		if !seen[cur] {
			seen[cur] = true
			dirs = append(dirs, cur)
		}
		switch name {
		case ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, name)
		info, err := os.Lstat(next)
		if err != nil {
			return next, dirs, err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			if links++; links > maxSymlinks {
				return next, dirs, errors.New("too many levels of symbolic links")
			}
			target, err := os.Readlink(next)
			if err != nil {
				return next, dirs, err
			}
			if filepath.IsAbs(target) {
				cur = "/"
			}
			rest = append(lookupNames(target), rest...)
			continue
		}
		if len(rest) > 0 && !info.IsDir() {
			return next, dirs, fmt.Errorf("%s: %w", next, syscall.ENOTDIR)
		}
		cur = next
	}
	return cur, dirs, nil
}

func names(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return r == '/' })
}

func lookupNames(p string) []string {
	out := names(p)
	if strings.HasSuffix(p, "/") {
		// A trailing slash requires a directory even in a symlink target.
		out = append(out, ".")
	}
	return out
}

func readRegularContent(p string) (string, error) {
	dir, err := safepath.OpenDirNoFollow(filepath.Dir(p))
	if err != nil {
		return "", err
	}
	defer func() { _ = dir.Close() }()
	file, err := dir.OpenFile(filepath.Base(p), os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("mutation target is not a regular file")
	}
	return readConfigContent(file)
}

// Targets describes each mutation target, in order, as Collect does.
func Targets(targets []antispam.Target) []antispam.TargetFacts {
	out := make([]antispam.TargetFacts, 0, len(targets))
	for _, t := range targets {
		out = append(out, targetFacts(t))
	}
	return out
}

// targetFacts describes one mutation target.
func targetFacts(t antispam.Target) antispam.TargetFacts {
	f := antispam.TargetFacts{Target: t}
	if f.Parents, f.Err = chain(filepath.Dir(t.Path)); f.Err != nil {
		return f
	}
	if last := f.Parents[len(f.Parents)-1]; !last.Mode.IsDir() {
		return f
	}
	facts, err := pathFacts(t.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		f.Missing = true
		return f
	case err != nil:
		f.Err = err
		return f
	}
	f.File = facts
	if targetSafeToRead(f) {
		f.Content, f.Err = readRegularContent(t.Path)
	}
	return f
}

func targetSafeToRead(f antispam.TargetFacts) bool {
	protected := func(p antispam.PathFacts) bool {
		return p.UID == 0 && p.Mode.Perm()&0o022 == 0 && !p.ExtACL
	}
	if !f.File.Mode.IsRegular() || !protected(f.File) {
		return false
	}
	for _, parent := range f.Parents {
		if !parent.Mode.IsDir() || !protected(parent) {
			return false
		}
	}
	return true
}
