package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLooksLikeCpanelRestoreStaging_RecognisesProductionPath(t *testing.T) {
	// Real path observed during a 2026-04-28 cPanel package restore: cpanel
	// extracts the user backup tar as root into this staging tree before
	// re-extracting it as the user into the actual home directory. Both
	// extractions trigger fanotify events; the user-context one carries the
	// real signal, so the staging-side anomalous-location warning is a
	// duplicate.
	got := looksLikeCpanelRestoreStaging(
		"/home/cpanelpkgrestore.TMP.work.79d118fd/unsafe_to_read_archive/" +
			"backup-4.28.2026_15-00-49_albright23/homedir/public_html/" +
			"wp-content/uploads/wpo/server-signature/on/test.php")
	if !got {
		t.Error("expected production cpanelpkgrestore staging path to be recognised")
	}
}

func TestLooksLikeCpanelRestoreStaging_RejectsAttackerOwnedSubdir(t *testing.T) {
	// A regular user account at /home/<user>/ has no way to create a
	// sibling like /home/<user>/cpanelpkgrestore.TMP.work.X/, but a
	// well-meaning operator could still drop one inside a user dir.
	// Recogniser must require the staging marker to sit directly under
	// /home (where only root can create directories), not nested under
	// any user-owned directory.
	cases := []string{
		"/home/attacker/cpanelpkgrestore.TMP.work.79d118fd/x.php",
		"/home/attacker/public_html/cpanelpkgrestore.TMP.work.79d118fd/x.php",
		"/tmp/cpanelpkgrestore.TMP.work.79d118fd/x.php",
		"/var/cpanelpkgrestore.TMP.work.79d118fd/x.php",
		"/cpanelpkgrestore.TMP.work.79d118fd/x.php",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			if looksLikeCpanelRestoreStaging(p) {
				t.Errorf("attacker-controllable path %s must NOT be recognised as cpanel staging", p)
			}
		})
	}
}

func TestLooksLikeCpanelRestoreStaging_RejectsMalformedTokens(t *testing.T) {
	// The marker is followed by cpanel random hex/alphanumeric id. An
	// operator-spoofed bare marker, or one with non-alphanumeric tail,
	// must not qualify.
	cases := []string{
		"/home/cpanelpkgrestore.TMP.work./x.php",           // empty token
		"/home/cpanelpkgrestore.TMP.work/x.php",            // no dot+token at all
		"/home/cpanelpkgrestore.TMP.work.../x.php",         // dots only
		"/home/cpanelpkgrestore.TMP.work.has spaces/x.php", // space in token
		"/home/cpanelpkgrestore.TMP.work.a/x.php",          // 1-char token (too short)
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			if looksLikeCpanelRestoreStaging(p) {
				t.Errorf("malformed staging token in %s must not qualify", p)
			}
		})
	}
}

func TestLooksLikeCpanelRestoreStaging_AcceptsAlphanumericIDs(t *testing.T) {
	// cpanel uses random alphanumeric ids of varying length. Stay
	// permissive on the exact alphabet so a future cpanel change in id
	// generation does not silently re-introduce duplicate alerts.
	cases := []string{
		"/home/cpanelpkgrestore.TMP.work.79d118fd/x.php",
		"/home/cpanelpkgrestore.TMP.work.ABCD1234/x.php",
		"/home/cpanelpkgrestore.TMP.work.1234567890abcdef/x.php",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			if !looksLikeCpanelRestoreStaging(p) {
				t.Errorf("alphanumeric id in %s should qualify", p)
			}
		})
	}
}

func TestLooksLikeWPOptimizeProbe_RecognisesProductionFile(t *testing.T) {
	// Build the directory shape WP-Optimize lays down: an installed plugin
	// at wp-content/plugins/wp-optimize/ and a tiny probe file at
	// wp-content/uploads/wpo/server-signature/on/test.php.
	wpRoot := t.TempDir()
	mustMkdirAll(t, filepath.Join(wpRoot, "wp-content", "plugins", "wp-optimize"))
	mustMkdirAll(t, filepath.Join(wpRoot, "wp-content", "uploads", "wpo", "server-signature", "on"))
	probe := filepath.Join(wpRoot, "wp-content", "uploads", "wpo", "server-signature", "on", "test.php")
	content := []byte(`<?php header("Server-Signature: on"); ?>` + "\n")
	mustWriteFile(t, probe, content)

	if !looksLikeWPOptimizeProbe(probe, content) {
		t.Error("expected WP-Optimize probe file with installed plugin to qualify")
	}
}

func TestLooksLikeWPOptimizeProbe_RejectsWhenPluginNotInstalled(t *testing.T) {
	// The wpo directory shape exists but the plugin is missing: an
	// attacker who creates wp-content/uploads/wpo/something.php on a
	// site that does not actually run WP-Optimize must NOT be granted
	// the suppression.
	wpRoot := t.TempDir()
	mustMkdirAll(t, filepath.Join(wpRoot, "wp-content", "uploads", "wpo"))
	probe := filepath.Join(wpRoot, "wp-content", "uploads", "wpo", "test.php")
	content := []byte(`<?php header("X: y"); ?>`)
	mustWriteFile(t, probe, content)

	// Filename matches; plugin is the missing gate. The recogniser
	// must NOT trust path + filename alone: if the wp-optimize plugin
	// isn't installed, the file is not a WP-Optimize probe and the
	// suppression must not apply.
	if looksLikeWPOptimizeProbe(probe, content) {
		t.Error("WP-Optimize recogniser must require the plugin to actually be installed")
	}
}

func TestLooksLikeWPOptimizeProbe_RejectsLargeFiles(t *testing.T) {
	wpRoot := t.TempDir()
	mustMkdirAll(t, filepath.Join(wpRoot, "wp-content", "plugins", "wp-optimize"))
	mustMkdirAll(t, filepath.Join(wpRoot, "wp-content", "uploads", "wpo"))
	probe := filepath.Join(wpRoot, "wp-content", "uploads", "wpo", "test.php")
	mustWriteFile(t, probe, []byte("<?php\n"))

	// Anything over the 512-byte size cap fails the shape gate, even on a
	// site that does run WP-Optimize. The attacker payload simply has to
	// be larger than the cap to be rejected here.
	big := []byte(strings.Repeat("// padding\n", 60)) // > 512 bytes
	if looksLikeWPOptimizeProbe(probe, big) {
		t.Error("WP-Optimize recogniser must reject files larger than the size cap")
	}
}

func TestLooksLikeWPOptimizeProbe_RejectsExecutionPrimitives(t *testing.T) {
	wpRoot := t.TempDir()
	mustMkdirAll(t, filepath.Join(wpRoot, "wp-content", "plugins", "wp-optimize"))
	mustMkdirAll(t, filepath.Join(wpRoot, "wp-content", "uploads", "wpo"))
	probe := filepath.Join(wpRoot, "wp-content", "uploads", "wpo", "test.php")
	mustWriteFile(t, probe, []byte("<?php\n"))

	// A short file in the wpo directory that happens to use any PHP
	// execution primitive or superglobal must not qualify, even though
	// the signature scanner running before this recogniser may not have
	// caught the specific shape. Defence in depth: the recogniser gates
	// suppression on a content shape WP-Optimize probes never use.
	dangerous := [][]byte{
		[]byte(`<?php @eval($_POST['c']);`),
		[]byte(`<?php passthru($cmd);`),
		[]byte(`<?php include 'x.php';`),
		[]byte(`<?php $x = $_GET['v'];`),
		[]byte(`<?php echo base64_decode('aGV5');`),
		[]byte("<?php echo \u0060id\u0060;"),
	}
	for i, c := range dangerous {
		label := []byte("case ")
		label = append(label, byte('0'+i))
		t.Run(string(label), func(t *testing.T) {
			if looksLikeWPOptimizeProbe(probe, c) {
				t.Errorf("WP-Optimize recogniser must reject files containing execution primitives: %q", c)
			}
		})
	}
}

func TestLooksLikeWPOptimizeProbe_RejectsPathsOutsideWpoDir(t *testing.T) {
	wpRoot := t.TempDir()
	mustMkdirAll(t, filepath.Join(wpRoot, "wp-content", "plugins", "wp-optimize"))
	mustMkdirAll(t, filepath.Join(wpRoot, "wp-content", "uploads", "other"))
	probe := filepath.Join(wpRoot, "wp-content", "uploads", "other", "x.php")
	mustWriteFile(t, probe, []byte(`<?php`))

	// The recogniser is scoped to /uploads/wpo/. Files elsewhere under
	// uploads must keep their normal anomalous-location warning even when
	// the WP-Optimize plugin is installed.
	if looksLikeWPOptimizeProbe(probe, []byte(`<?php`)) {
		t.Error("WP-Optimize recogniser must only fire for paths under /uploads/wpo/")
	}
}

func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestSignalEagerReconcile_FiresOnceAtThresholdCrossing(t *testing.T) {
	// signalEagerReconcile is the cross-platform helper that
	// maybeTriggerEagerReconcile delegates to. We test it directly so
	// the trigger logic is validated regardless of which build tags
	// are active. Channel is the same shape as the production one:
	// buffered cap-1, non-blocking send.
	sig := make(chan struct{}, 1)

	// Counts strictly below threshold must not fire.
	for i := int64(1); i < 500; i++ {
		signalEagerReconcile(sig, i, 500)
	}
	select {
	case <-sig:
		t.Error("eager reconcile must not fire before threshold")
	default:
	}

	// Hitting the threshold fires exactly once.
	signalEagerReconcile(sig, 500, 500)
	select {
	case <-sig:
		// OK
	default:
		t.Error("eager reconcile must fire when count reaches threshold")
	}

	// Counts above threshold within the same window must not refire
	// (the channel cap-1 keeps the send non-blocking even if not
	// drained, but the count != threshold guard short-circuits early
	// so we never even attempt the send). The next reconcile is armed
	// only when the receiver resets its counter and a fresh burst
	// reaches the threshold again.
	for i := int64(501); i < 600; i++ {
		signalEagerReconcile(sig, i, 500)
	}
	select {
	case <-sig:
		t.Error("eager reconcile must not refire above threshold without draining")
	default:
	}
}

func TestSignalEagerReconcile_TolerantOfNilChannel(t *testing.T) {
	// Helper must be a no-op when the signal channel is nil so partial
	// FileMonitor structs constructed in unit tests do not panic.
	signalEagerReconcile(nil, 500, 500)
	// no panic = pass
}

func TestSignalEagerReconcile_NonBlockingWhenChannelFull(t *testing.T) {
	// Pre-fill the channel to cap so the next send must hit the default
	// branch. signalEagerReconcile must return without blocking even
	// though the receive side is stalled.
	sig := make(chan struct{}, 1)
	sig <- struct{}{}

	done := make(chan struct{})
	go func() {
		signalEagerReconcile(sig, 500, 500)
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(50 * time.Millisecond):
		t.Error("signalEagerReconcile blocked on a full channel; the send must be non-blocking")
	}
}
