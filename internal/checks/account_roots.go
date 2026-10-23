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

// listAccountHomes provides a best-effort account inventory. Stateful scanners
// use readAccountHomes so a partial inventory cannot retire unseen findings.
func listAccountHomes() ([]accountHome, error) {
	homes, err := readAccountHomes()
	if len(homes) > 0 {
		return homes, nil
	}
	return homes, err
}

// readAccountHomes skips absent roots, but reports other read failures even
// when another root supplies accounts.
func readAccountHomes() ([]accountHome, error) {
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
	return homes, firstErr
}

// AccountHomeRoots returns the directories hosting accounts live under on
// this platform: /home, or /var/www/vhosts on Plesk.
func AccountHomeRoots() []string {
	return accountHomeRoots()
}

// accountHomeDir resolves an account's home directory: the first root that
// holds it, then a registered cPanel account's home on another partition,
// or the first root when it exists nowhere (callers that need existence
// check it themselves).
func accountHomeDir(account string) string {
	roots := accountHomeRoots()
	if home, ok := accountHomeUnder(roots, account); ok {
		return home
	}
	if home, ok := registeredAccountHome(account); ok {
		return home
	}
	return defaultAccountHome(roots, account)
}

// AccountHomeDirIn is accountHomeDir over the given roots, without the
// registry lookup.
func AccountHomeDirIn(roots []string, account string) string {
	if home, ok := accountHomeUnder(roots, account); ok {
		return home
	}
	return defaultAccountHome(roots, account)
}

func accountHomeUnder(roots []string, account string) (string, bool) {
	for _, root := range roots {
		candidate := filepath.Join(root, account)
		if _, err := osFS.Stat(candidate); err == nil {
			return candidate, true
		}
	}
	return "", false
}

func defaultAccountHome(roots []string, account string) string {
	if len(roots) == 0 {
		return filepath.Join("/home", account)
	}
	return filepath.Join(roots[0], account)
}

// registeredAccountHome resolves a cPanel account that lives outside every
// account root: HOMEMATCH places new accounts on any matching partition
// (/home2, /home3, ...). The registry decides the name is an account and
// passwd names its home; the home must be a real directory named after the
// account, so a redirected or symlinked home is never scanned in its name.
func registeredAccountHome(account string) (string, bool) {
	if !validAccountName.MatchString(account) {
		return "", false
	}
	if _, err := osFS.Stat(filepath.Join("/var/cpanel/users", account)); err != nil {
		return "", false
	}
	home := defaultUIDCache.HomeDir(account)
	if !filepath.IsAbs(home) || filepath.Base(home) != account {
		return "", false
	}
	info, err := osFS.Lstat(home)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return filepath.Clean(home), true
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
	return accountRootOfAt(path, accountHomeRoots())
}

func accountRootOfAt(path string, roots []string) (root, account string, ok bool) {
	clean := filepath.Clean(path)
	for _, r := range roots {
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

// accountNameInTextAt returns the account named by the first
// "<root>/<account>/" reference in free text (a finding message or
// details), or "" when none is present.
func accountNameInTextAt(text string, roots []string) string {
	for _, root := range roots {
		prefix := filepath.Clean(root) + string(filepath.Separator)
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
