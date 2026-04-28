package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLooksLikeCpanelRestoreStaging_RecognisesProductionPath(t *testing.T) {
	got := LooksLikeCpanelRestoreStaging(
		"/home/cpanelpkgrestore.TMP.work.79d118fd/unsafe_to_read_archive/" +
			"backup-4.28.2026_15-00-49_albright23/homedir/public_html/" +
			"wp-content/uploads/wpo/server-signature/on/test.php")
	if !got {
		t.Error("expected production cpanelpkgrestore staging path to be recognised")
	}
}

func TestLooksLikeCpanelRestoreStaging_RejectsAttackerOwnedSubdir(t *testing.T) {
	cases := []string{
		"/home/attacker/cpanelpkgrestore.TMP.work.79d118fd/x.php",
		"/home/attacker/public_html/cpanelpkgrestore.TMP.work.79d118fd/x.php",
		"/tmp/cpanelpkgrestore.TMP.work.79d118fd/x.php",
		"/var/cpanelpkgrestore.TMP.work.79d118fd/x.php",
		"/cpanelpkgrestore.TMP.work.79d118fd/x.php",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			if LooksLikeCpanelRestoreStaging(p) {
				t.Errorf("attacker-controllable path %s must NOT be recognised", p)
			}
		})
	}
}

func TestLooksLikeCpanelRestoreStaging_RejectsMalformedTokens(t *testing.T) {
	cases := []string{
		"/home/cpanelpkgrestore.TMP.work./x.php",
		"/home/cpanelpkgrestore.TMP.work/x.php",
		"/home/cpanelpkgrestore.TMP.work.../x.php",
		"/home/cpanelpkgrestore.TMP.work.has spaces/x.php",
		"/home/cpanelpkgrestore.TMP.work.a/x.php",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			if LooksLikeCpanelRestoreStaging(p) {
				t.Errorf("malformed staging token in %s must not qualify", p)
			}
		})
	}
}

func TestLooksLikeCpanelRestoreStaging_AcceptsAlphanumericIDs(t *testing.T) {
	cases := []string{
		"/home/cpanelpkgrestore.TMP.work.79d118fd/x.php",
		"/home/cpanelpkgrestore.TMP.work.ABCD1234/x.php",
		"/home/cpanelpkgrestore.TMP.work.1234567890abcdef/x.php",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			if !LooksLikeCpanelRestoreStaging(p) {
				t.Errorf("alphanumeric id in %s should qualify", p)
			}
		})
	}
}

func TestLooksLikeWPOptimizeProbeByPath_RecognisesServerSignatureProbe(t *testing.T) {
	wpRoot := t.TempDir()
	mustMkdirInChecks(t, filepath.Join(wpRoot, "wp-content", "plugins", "wp-optimize"))
	mustMkdirInChecks(t, filepath.Join(wpRoot, "wp-content", "uploads", "wpo", "server-signature", "on"))
	probe := filepath.Join(wpRoot, "wp-content", "uploads", "wpo", "server-signature", "on", "test.php")
	mustWriteFileInChecks(t, probe, []byte(`<?php`))

	if !LooksLikeWPOptimizeProbeByPath(probe) {
		t.Error("expected server-signature/on/test.php to be recognised when plugin is installed")
	}
}

func TestLooksLikeWPOptimizeProbeByPath_RecognisesModuleLoadedProbe(t *testing.T) {
	wpRoot := t.TempDir()
	mustMkdirInChecks(t, filepath.Join(wpRoot, "wp-content", "plugins", "wp-optimize"))
	mustMkdirInChecks(t, filepath.Join(wpRoot, "wp-content", "uploads", "wpo", "module-loaded", "headers", "server-signature"))
	probe := filepath.Join(wpRoot, "wp-content", "uploads", "wpo", "module-loaded", "headers", "server-signature", "test.php")
	mustWriteFileInChecks(t, probe, []byte(`<?php`))

	if !LooksLikeWPOptimizeProbeByPath(probe) {
		t.Error("expected module-loaded/headers/server-signature/test.php to be recognised")
	}
}

func TestLooksLikeWPOptimizeProbeByPath_RejectsWhenPluginNotInstalled(t *testing.T) {
	wpRoot := t.TempDir()
	mustMkdirInChecks(t, filepath.Join(wpRoot, "wp-content", "uploads", "wpo"))
	probe := filepath.Join(wpRoot, "wp-content", "uploads", "wpo", "test.php")
	mustWriteFileInChecks(t, probe, []byte(`<?php`))

	if LooksLikeWPOptimizeProbeByPath(probe) {
		t.Error("must require the wp-optimize plugin to actually be installed")
	}
}

func TestLooksLikeWPOptimizeProbeByPath_RejectsNonTestPhpFilenames(t *testing.T) {
	wpRoot := t.TempDir()
	mustMkdirInChecks(t, filepath.Join(wpRoot, "wp-content", "plugins", "wp-optimize"))
	mustMkdirInChecks(t, filepath.Join(wpRoot, "wp-content", "uploads", "wpo"))
	// Attacker drops a webshell at /uploads/wpo/ but with a different
	// name; the path-only recogniser must NOT suppress it on filename
	// alone since the deep-scan path cannot read content to apply the
	// shape gate.
	probe := filepath.Join(wpRoot, "wp-content", "uploads", "wpo", "webshell.php")
	mustWriteFileInChecks(t, probe, []byte(`<?php`))

	if LooksLikeWPOptimizeProbeByPath(probe) {
		t.Error("must reject filenames other than test.php under /wpo/")
	}
}

func TestLooksLikeWPOptimizeProbeByPath_RejectsPathsOutsideWpoDir(t *testing.T) {
	wpRoot := t.TempDir()
	mustMkdirInChecks(t, filepath.Join(wpRoot, "wp-content", "plugins", "wp-optimize"))
	mustMkdirInChecks(t, filepath.Join(wpRoot, "wp-content", "uploads", "other"))
	probe := filepath.Join(wpRoot, "wp-content", "uploads", "other", "test.php")
	mustWriteFileInChecks(t, probe, []byte(`<?php`))

	if LooksLikeWPOptimizeProbeByPath(probe) {
		t.Error("must only fire for paths under /wp-content/uploads/wpo/")
	}
}

func mustMkdirInChecks(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func mustWriteFileInChecks(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
