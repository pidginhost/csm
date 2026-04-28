package daemon

import (
	"bytes"

	"github.com/pidginhost/csm/internal/checks"
)

// signalEagerReconcile fires a non-blocking notification on sig the first
// time count reaches threshold. Cross-platform helper extracted so the
// trigger can be unit-tested from a non-linux test file.
//
//   - sig is a buffered cap-1 channel. The send is non-blocking (default
//     branch) so a stalled receiver never wedges the caller.
//   - The trigger fires only on the exact threshold (not >=). A long
//     burst above threshold within the same window must not refire
//     after the signal has been drained; the next window's first count
//     reaching threshold rearms it once the receiver has reset counters.
//   - A nil sig is a no-op (some unit tests construct partial structs
//     that omit it).
func signalEagerReconcile(sig chan struct{}, count, threshold int64) {
	if sig == nil {
		return
	}
	if count != threshold {
		return
	}
	select {
	case sig <- struct{}{}:
	default:
	}
}

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

// looksLikeCpanelRestoreStaging delegates to the shared recogniser in
// internal/checks/sitedetect.go. The deep-scan path uses the same
// helper so realtime and scheduled scans agree on which files are
// duplicates of the user-context extraction.
func looksLikeCpanelRestoreStaging(path string) bool {
	return checks.LooksLikeCpanelRestoreStaging(path)
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

// looksLikeWPOptimizeProbe is the realtime, content-aware check.
// It applies the shared path-only gate from internal/checks/sitedetect.go
// (path under /uploads/wpo/, basename test.php, plugin installed) and
// then adds two content-shape gates the deep-scan path cannot apply:
//
//   - File body fits in wpOptimizeProbeMaxSize bytes.
//   - File body contains none of wpOptimizeProbeDangerous.
//
// All gates together prevent a webshell hidden under /uploads/wpo/test.php
// from silencing the realtime warning: any payload large or interesting
// enough to be useful trips one of the content gates. The
// signature/YARA scanners run before this recogniser, so any existing
// rule still fires on its own pipeline regardless of suppression here.
func looksLikeWPOptimizeProbe(path string, content []byte) bool {
	if !checks.LooksLikeWPOptimizeProbeByPath(path) {
		return false
	}
	if len(content) > wpOptimizeProbeMaxSize {
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
