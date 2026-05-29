package checks

import (
	"os"
	"path/filepath"
	"strings"
)

// Recognisers used by the realtime fanotify restore/probe dedup logic.
// The scheduled file index deliberately does not call these as scan skips:
// upload PHP is indexed first and then classified by content.

// LooksLikeCpanelRestoreStaging recognises files inside cPanel's
// pkgacct/restorepkg staging tree. cPanel extracts the user backup
// as root into /home/cpanelpkgrestore.TMP.work.<id>/ for inspection,
// then re-extracts it under the user identity into /home/<account>/.
// Both extractions raise events; the user-context one carries the
// real signal, so the staging-side alert is a duplicate.
//
// The recogniser requires the marker to sit directly under /home (the
// only place cPanel ever creates it) plus a non-empty alphanumeric id
// of >=2 chars. A user account at /home/<user>/ cannot create
// siblings of itself, so this gate cannot be spoofed by a non-root
// attacker.
func LooksLikeCpanelRestoreStaging(path string) bool {
	const homeRoot = "/home"
	const marker = "/cpanelpkgrestore.TMP.work."

	idx := strings.Index(path, marker)
	if idx < 0 {
		return false
	}
	if idx != len(homeRoot) {
		return false
	}
	if !strings.HasPrefix(path, homeRoot) {
		return false
	}

	rest := path[idx+len(marker):]
	if rest == "" {
		return false
	}
	end := strings.IndexByte(rest, '/')
	var token string
	if end < 0 {
		token = rest
	} else {
		token = rest[:end]
	}
	if len(token) < 2 {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		default:
			return false
		}
	}
	return true
}

// LooksLikeWPOptimizeProbeByPath recognises WP-Optimize's per-server
// probe files using path structure alone. WP-Optimize writes tiny
// <?php files to /wp-content/uploads/wpo/.../test.php to test whether
// the host honours certain Apache/Nginx directives.
//
// Path-only gates (no content read):
//
//  1. Path lies under /wp-content/uploads/wpo/.
//  2. The basename is exactly "test.php" (the literal filename
//     WP-Optimize uses for these probes; an attacker dropping
//     /uploads/wpo/webshell.php fails this gate and continues to
//     the standard alert).
//  3. The wp-optimize plugin directory is actually present in this
//     site's wp-content/plugins/ tree (filesystem stat).
//
// The realtime path additionally applies a content shape gate before
// suppressing the duplicate alert, so the path predicate here stays
// narrow to the literal probe filename and installed plugin directory.
func LooksLikeWPOptimizeProbeByPath(path string) bool {
	const marker = "/wp-content/uploads/wpo/"
	if !strings.Contains(path, marker) {
		return false
	}
	if filepath.Base(path) != "test.php" {
		return false
	}
	uploadsIdx := strings.Index(path, "/wp-content/uploads/")
	if uploadsIdx < 0 {
		return false
	}
	pluginDir := path[:uploadsIdx] + "/wp-content/plugins/wp-optimize"
	st, err := os.Stat(pluginDir)
	if err != nil || !st.IsDir() {
		return false
	}
	return true
}
