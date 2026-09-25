package checks

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pidginhost/csm/internal/config"
)

type docrootScanRoot struct {
	path    string
	account string
}

// SetUserdataDomainsPathForTest points the cPanel domain map at path and
// returns a function that restores the previous location. For tests only:
// packages outside checks cannot reach the injectable filesystem, so this is
// how they exercise addon-domain docroots.
func SetUserdataDomainsPathForTest(path string) func() {
	prev := userdataDomainsPath
	userdataDomainsPath = path
	return func() { userdataDomainsPath = prev }
}

// validatedDocroots lists the document roots the per-site performance checks
// scan.
//
// ResolveWebRoots alone resolves to /home/*/public_html on cPanel, which misses
// every addon domain: those are served from /home/<user>/<domain>/ and never
// appear beneath public_html. On a live host that hid 177 of 277 WordPress
// installs from the WP-Cron check, so the fix could never reach them. cPanel's own domain map is the
// authoritative list, and is already how the exposed-files and php-config
// checks enumerate document roots.
//
// Roots are de-duplicated and path-sorted. Nested roots stay in the list so
// each gets its own full depth allowance; the scanner assigns the nested
// subtree to the more-specific root to avoid duplicate work and findings.
func validatedDocroots(cfg *config.Config) []string {
	rootSet, _ := validatedDocrootSet(cfg)
	roots := make([]string, 0, len(rootSet))
	for _, root := range rootSet {
		roots = append(roots, root.path)
	}
	return roots
}

// ResolveValidatedDocroots returns the same validated roots the scans use.
// Remediation callers use it so a finding from an addon domain remains inside
// the exact root authorized by cPanel's map.
func ResolveValidatedDocroots(cfg *config.Config) []string {
	return validatedDocroots(cfg)
}

func validatedDocrootSet(cfg *config.Config) ([]docrootScanRoot, bool) {
	configured := ResolveWebRoots(cfg)
	byPath := make(map[string]docrootScanRoot, len(configured))
	for _, root := range configured {
		clean := filepath.Clean(root)
		byPath[clean] = docrootScanRoot{path: clean, account: accountFromPath(clean)}
	}

	complete := true
	data, err := osFS.ReadFile(userdataDomainsPath)
	if err != nil {
		if vhostMapFailureIsIncomplete(err) {
			complete = false
		}
		return sortedDocrootScanRoots(byPath), complete
	}
	vhosts, parsedComplete := parseUserdataDomainRootsChecked(string(data))
	complete = complete && parsedComplete
	attempted := make(map[string]struct{}, len(vhosts))
	for _, vhost := range vhosts {
		clean := filepath.Clean(vhost.docroot)
		key := vhost.user + "\x00" + clean
		if _, duplicate := attempted[key]; duplicate {
			continue
		}
		attempted[key] = struct{}{}
		homeBase, accountHome, safe := docrootMapAccountHome(vhost.user, clean, configured)
		if !safe {
			complete = false
			continue
		}
		exists, pathComplete := docrootMapRootIsSafe(homeBase, accountHome, clean)
		if !pathComplete {
			complete = false
		}
		if !exists {
			continue
		}
		byPath[clean] = docrootScanRoot{path: clean, account: vhost.user}
	}
	return sortedDocrootScanRoots(byPath), complete
}

func sortedDocrootScanRoots(byPath map[string]docrootScanRoot) []docrootScanRoot {
	roots := make([]docrootScanRoot, 0, len(byPath))
	for _, root := range byPath {
		roots = append(roots, root)
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].path < roots[j].path })
	return roots
}

func docrootMapAccountHome(user, docroot string, configured []string) (homeBase, accountHome string, ok bool) {
	clean := filepath.Clean(docroot)
	if !filepath.IsAbs(clean) {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) >= 3 && isHomeVolumeName(parts[0]) && parts[1] == user {
		homeBase = filepath.Join(string(filepath.Separator), parts[0])
		accountHome = filepath.Join(homeBase, user)
		return homeBase, accountHome, clean != accountHome
	}

	// Explicit account_roots may point into a chroot-style test or custom
	// mount. Only extend a map root to a sibling when the configured root
	// already anchors that same /home/USER boundary.
	for _, configuredRoot := range configured {
		rootParts := strings.Split(strings.TrimPrefix(filepath.Clean(configuredRoot), string(filepath.Separator)), string(filepath.Separator))
		for i := 0; i+1 < len(rootParts); i++ {
			if rootParts[i] != "home" || rootParts[i+1] != user {
				continue
			}
			homeBaseParts := append([]string{string(filepath.Separator)}, rootParts[:i+1]...)
			homeBase = filepath.Join(homeBaseParts...)
			accountHome = filepath.Join(homeBase, user)
			if filepath.Clean(configuredRoot) != accountHome &&
				isPathWithinOrEqual(configuredRoot, accountHome) &&
				clean != accountHome && isPathWithinOrEqual(clean, accountHome) {
				return homeBase, accountHome, true
			}
		}
	}
	return "", "", false
}

func isHomeVolumeName(name string) bool {
	if name == "home" {
		return true
	}
	if !strings.HasPrefix(name, "home") || len(name) == len("home") {
		return false
	}
	for _, r := range name[len("home"):] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// docrootMapRootIsSafe rejects symlinks at every component from the home mount
// through the docroot. Stat on only the final path would follow an intermediate
// symlink and let a malformed map redirect the scan outside the account.
func docrootMapRootIsSafe(homeBase, accountHome, root string) (exists, complete bool) {
	if !isPathWithinOrEqual(accountHome, homeBase) ||
		!isPathWithinOrEqual(root, accountHome) || root == accountHome {
		return false, false
	}
	rel, err := filepath.Rel(homeBase, root)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false, false
	}
	paths := []string{homeBase}
	current := homeBase
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		paths = append(paths, current)
	}
	for _, path := range paths {
		info, statErr := osFS.Lstat(path)
		if statErr != nil {
			if errors.Is(statErr, fs.ErrNotExist) {
				return false, true
			}
			return false, false
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return false, false
		}
	}
	return true, true
}
