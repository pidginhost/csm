package checks

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// accountHomeRoots answers "where do hosting accounts live" for every
// account-scoped check, remediation and re-check. A seam so tests can point
// the package at a temp tree; production follows platform detection.
var accountHomeRoots = func() []string { return platform.Detect().AccountHomeRoots() }

// accountHome is one account directory under one of the roots.
type accountHome struct {
	Root  string
	Entry os.DirEntry
}

// Path is the account's home directory.
func (h accountHome) Path() string { return filepath.Join(h.Root, h.Entry.Name()) }

// Name is the account name.
func (h accountHome) Name() string { return h.Entry.Name() }

// listAccountHomes enumerates every account directory under every root.
// A root that does not exist is skipped; any other read error is returned
// so callers can tell a broken enumeration from an empty host.
func listAccountHomes() ([]accountHome, error) {
	var homes []accountHome
	var firstErr error
	for _, root := range accountHomeRoots() {
		entries, err := osFS.ReadDir(root)
		if err != nil {
			if !os.IsNotExist(err) && firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, e := range entries {
			homes = append(homes, accountHome{Root: root, Entry: e})
		}
	}
	if len(homes) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return homes, nil
}

// accountHomeDir resolves an account's home directory: the first root that
// holds it, or the first root when it exists nowhere (callers that need
// existence check it themselves).
func accountHomeDir(account string) string {
	roots := accountHomeRoots()
	for _, root := range roots {
		candidate := filepath.Join(root, account)
		if _, err := osFS.Stat(candidate); err == nil {
			return candidate
		}
	}
	if len(roots) == 0 {
		return filepath.Join("/home", account)
	}
	return filepath.Join(roots[0], account)
}

// accountHomeGlob globs "<root>/<pattern>" under every root and returns the
// concatenated matches. pattern typically starts with "*" (any account).
func accountHomeGlob(pattern string) ([]string, error) {
	var out []string
	var firstErr error
	for _, root := range accountHomeRoots() {
		matches, err := osFS.Glob(filepath.Join(root, pattern))
		if err != nil && firstErr == nil {
			firstErr = err
		}
		out = append(out, matches...)
	}
	if out == nil {
		return nil, firstErr
	}
	return out, nil
}

// accountHomePatterns returns "<root>/*" for every account root: the glob
// form of "every account home".
func accountHomePatterns() []string {
	roots := accountHomeRoots()
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		out = append(out, filepath.Join(root, "*"))
	}
	return out
}

// accountHomeSubPatterns returns "<root>/*/<sub>" for every account root.
func accountHomeSubPatterns(sub string) []string {
	roots := accountHomeRoots()
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		out = append(out, filepath.Join(root, "*", sub))
	}
	return out
}

// accountRootOf reports the root and account a path belongs to. The path
// must lie strictly inside an account directory: a root or an account home
// itself is not "inside an account".
func accountRootOf(path string) (root, account string, ok bool) {
	clean := filepath.Clean(path)
	for _, r := range accountHomeRoots() {
		r = filepath.Clean(r)
		rest, found := strings.CutPrefix(clean, r+string(filepath.Separator))
		if !found {
			continue
		}
		account, tail, hasTail := strings.Cut(rest, string(filepath.Separator))
		if account == "" || !hasTail || tail == "" {
			continue
		}
		return r, account, true
	}
	return "", "", false
}

// isAccountRoot reports whether dir is one of the account roots.
func isAccountRoot(dir string) bool {
	clean := filepath.Clean(dir)
	for _, r := range accountHomeRoots() {
		if filepath.Clean(r) == clean {
			return true
		}
	}
	return false
}

// underAccountRoot reports whether path is at or below any account root.
func underAccountRoot(path string) bool {
	clean := filepath.Clean(path)
	for _, r := range accountHomeRoots() {
		r = filepath.Clean(r)
		if clean == r || strings.HasPrefix(clean, r+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// accountRootPrefixes returns every account root with a trailing separator
// (the prefix form used to test "is this path inside an account") followed
// by extra prefixes verbatim.
func accountRootPrefixes(extra ...string) []string {
	roots := accountHomeRoots()
	out := make([]string, 0, len(roots)+len(extra))
	for _, root := range roots {
		out = append(out, filepath.Clean(root)+string(filepath.Separator))
	}
	return append(out, extra...)
}

// accountNameInText returns the account named by the first
// "<root>/<account>/" reference in free text (a finding message or
// details), or "" when none is present.
func accountNameInText(text string) string {
	for _, prefix := range accountRootPrefixes() {
		idx := strings.Index(text, prefix)
		if idx < 0 {
			continue
		}
		rest := text[idx+len(prefix):]
		if slash := strings.IndexByte(rest, '/'); slash > 0 {
			return rest[:slash]
		}
	}
	return ""
}

// effectiveFixRoots returns the allowed roots for a remediation: an
// explicit override (tests redirect under t.TempDir()) wins; otherwise the
// account roots plus any extra system directories the action may touch.
func effectiveFixRoots(override []string, extra ...string) []string {
	if override != nil {
		return override
	}
	roots := append([]string(nil), accountHomeRoots()...)
	if cfg := config.Active(); cfg != nil {
		// Failed roots are excluded; doctor reports the resolution errors.
		// One tenant's symlink must not disable fixes for other accounts.
		configured, _ := platform.ResolveAccountRoots(cfg.AccountRoots)
		roots = append(roots, configured...)
	}
	return append(roots, extra...)
}

// quarantineExtraRoots are the non-account directories a quarantine may
// take a file from: the world-writable temp trees droppers land in.
var quarantineExtraRoots = []string{"/tmp", "/dev/shm", "/var/tmp"}
