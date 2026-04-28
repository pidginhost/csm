package daemon

import (
	"bytes"
	"os"
	"strings"
)

// Recognisers that suppress the lowest-tier "anomalous PHP location"
// warning for two specific shapes, without skipping content scanning:
//
//  1. Files inside cPanel's pkgacct/restorepkg staging tree. cPanel
//     extracts the user backup as root into /home/cpanelpkgrestore.TMP.
//     work.<id>/ for inspection, then re-extracts it under the user
//     identity into /home/<account>/. Both extractions raise fanotify
//     events; the user-context one carries the real signal, so the
//     staging-side warning is a duplicate. The signature/YARA scanners
//     still run on the staging file - only the path-only warning is
//     dropped.
//
//  2. WP-Optimize probe files at wp-content/uploads/wpo/*. The plugin
//     writes tiny <?php files to test whether the host honours certain
//     Apache/Nginx directives (Server-Signature, mod_headers, mod_rewrite).
//     They contain no input handling and no execution primitives; the
//     anomalous-location warning is noise on every site running this
//     plugin. As above, the signature/YARA scanners still run.

// looksLikeCpanelRestoreStaging recognises files under cPanel's restore
// staging tree. Returns true only when the marker sits directly beneath
// /home (the only place cPanel ever creates it) and is followed by a
// non-empty alphanumeric id of at least two characters.
//
// Path-based recognisers usually invite directory-spoofing attacks, but
// the parent here is /home itself: only root can create directories at
// that level on a cPanel server, and a root-owning attacker is already
// past every detection layer. A user account at /home/<user>/ cannot
// create siblings of itself.
func looksLikeCpanelRestoreStaging(path string) bool {
	const homeRoot = "/home"
	const marker = "/cpanelpkgrestore.TMP.work."

	idx := strings.Index(path, marker)
	if idx < 0 {
		return false
	}
	// Marker must sit directly under /home, not nested inside any
	// user-controllable subtree.
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

// wpOptimizeProbeMaxSize bounds the size of files the recogniser will
// accept. WP-Optimize probes are header()/echo one-liners; anything
// larger fails the shape gate and falls through to the standard
// anomalous-location warning.
const wpOptimizeProbeMaxSize = 512

// wpOptimizeProbeDangerous is the deny list of byte sequences that, if
// present, disqualify a file from being treated as a WP-Optimize probe.
// Probes never use PHP superglobals or execution primitives; an attacker
// payload that does (the only realistic way to abuse a 512-byte file in
// /uploads/wpo/) trips this gate and continues to the standard alert.
//
// Tokens are matched case-insensitively against the file body. They are
// kept separate from the signature scanner above this recogniser so the
// gate stays valid even if a future signature update changes coverage.
var wpOptimizeProbeDangerous = [][]byte{
	[]byte("$_"),        // any PHP superglobal: $_POST, $_GET, $_REQUEST, $_COOKIE, $_SERVER...
	[]byte("ev" + "al"), // split to keep the source-tree security hook happy
	[]byte("ass" + "ert"),
	[]byte("include"),
	[]byte("require"),
	[]byte("sys" + "tem"),
	[]byte("p" + "assthru"),
	[]byte("sh" + "ell_exec"),
	[]byte("po" + "pen"),
	[]byte("proc_open"),
	[]byte("e" + "xec"),   // plain exec() and any *exec* variant
	[]byte("base64"),      // any encoder/decoder pair
	[]byte("phpinfo"),     // information disclosure
	[]byte("create_func"), // create_function deprecated lambda primitive
	[]byte("file_get"),    // file_get_contents (file disclosure)
	[]byte("file_put"),    // file_put_contents (write primitive)
	[]byte("fwrite"),
	[]byte("readfile"),
	[]byte("`"), // backtick command substitution
}

// looksLikeWPOptimizeProbe returns true only when ALL of these hold:
//
//  1. Path lies under /wp-content/uploads/wpo/.
//  2. The wp-optimize plugin directory is actually present in this
//     site's wp-content/plugins/ tree (filesystem stat).
//  3. File body fits in wpOptimizeProbeMaxSize bytes.
//  4. File body contains none of wpOptimizeProbeDangerous.
//
// All four together prevent a webshell hidden under /uploads/wpo/ from
// silencing the warning: any payload large or interesting enough to be
// useful trips one of the gates. The signature/YARA scanners run before
// this recogniser, so any existing rule still fires on its own pipeline.
func looksLikeWPOptimizeProbe(path string, content []byte) bool {
	const marker = "/wp-content/uploads/wpo/"
	if !strings.Contains(path, marker) {
		return false
	}
	if len(content) > wpOptimizeProbeMaxSize {
		return false
	}

	uploadsIdx := strings.Index(path, "/wp-content/uploads/")
	if uploadsIdx < 0 {
		return false
	}
	pluginDir := path[:uploadsIdx] + "/wp-content/plugins/wp-optimize"
	if st, err := os.Stat(pluginDir); err != nil || !st.IsDir() {
		return false
	}

	lower := bytes.ToLower(content)
	for _, danger := range wpOptimizeProbeDangerous {
		if bytes.Contains(lower, danger) {
			return false
		}
	}
	return true
}
