package checks

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/contenttype"
	"github.com/pidginhost/csm/internal/wpcheck"
)

// webshellFlaggedFiles returns the files whose requests name a webshell
// caller, keyed by path; the value is true when the path is flagged because
// CSM removed the file. A Critical content finding alone is not enough: it
// also covers a site's own pages with injected code, and their visitors are
// not callers. Nil when nothing is flagged.
func webshellFlaggedFiles(latest []alert.Finding, removed []RemovedFile, docroots []string) map[string]bool {
	roots := NewDocrootIndex(docroots)
	var flagged map[string]bool
	add := func(path string, removal bool) {
		if !filepath.IsAbs(path) {
			return
		}
		path = filepath.Clean(path)
		if _, ok := flagged[path]; ok || !webshellCallerTarget(path, roots) {
			return
		}
		if flagged == nil {
			flagged = make(map[string]bool)
		}
		flagged[path] = removal
	}
	for _, f := range latest {
		if f.Severity == alert.Critical && malwareFileCheck(f.Check) {
			add(f.FilePath, false)
		}
	}
	for _, r := range removed {
		// A cleaned file is the site's own and still served. A quarantined
		// path that holds a file again counts only through a new finding:
		// the site may have been rebuilt.
		if r.Action != "quarantine" {
			continue
		}
		if _, err := osFS.Lstat(r.Path); os.IsNotExist(err) {
			add(r.Path, true)
		}
	}
	return flagged
}

// webshellCallerTarget reports whether a request for path runs a file that
// only its operator has a reason to request: PHP a web server executes, inside
// a document root, and not one of the site's entry points.
func webshellCallerTarget(path string, roots *DocrootIndex) bool {
	if !contenttype.IsExecutablePHPName(strings.ToLower(filepath.Base(path))) {
		return false
	}
	root := roots.Lookup(path)
	if root == "" || path == filepath.Join(root, "index.php") {
		return false
	}
	if shippedByRelease(path) {
		return false
	}
	// An entry file name proves nothing by itself: it is an entry point only
	// at the root of an install.
	dir := filepath.Dir(path)
	if wpcheck.DetectWPRoot(path) == dir {
		if _, err := osFS.Stat(filepath.Join(dir, "wp-includes", "version.php")); err == nil {
			return false
		}
	}
	return true
}
