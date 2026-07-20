package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// Header excerpt matching the real TimThumb 2.8.5 seen in the 2026-07-20
// cross-account incident. No exec/superglobal tokens, only TimThumb's own
// constants and version define.
const timThumbHead = `<?php
/*
 * TimThumb by Ben Gillbanks and Mark Maunder
 */
define ('VERSION', '2.8.5');
if(! defined('BLOCK_EXTERNAL_LEECHERS') ) 	define ('BLOCK_EXTERNAL_LEECHERS', false);
if(! defined('WEBSHOT_ENABLED') ) 	define ('WEBSHOT_ENABLED', false);
if(! defined('ALLOW_EXTERNAL') ) 	define ('ALLOW_EXTERNAL', false);
`

func TestLooksLikeTimThumb(t *testing.T) {
	if !looksLikeTimThumb([]byte(timThumbHead)) {
		t.Error("real TimThumb header not recognised")
	}
	// A generic theme thumbnail helper is not TimThumb.
	generic := []byte("<?php function theme_thumb($id){ return wp_get_attachment_image($id,'thumbnail'); }")
	if looksLikeTimThumb(generic) {
		t.Error("generic theme thumb.php misidentified as TimThumb")
	}
	// WebShot + external-leecher constants alone (no name) still identify it.
	byConst := []byte("<?php define('BLOCK_EXTERNAL_LEECHERS', true); if(WEBSHOT_ENABLED){}")
	if !looksLikeTimThumb(byConst) {
		t.Error("TimThumb identified only by its constants was missed")
	}
}

func TestParseTimThumbVersion(t *testing.T) {
	if v := parseTimThumbVersion([]byte(timThumbHead)); v != "2.8.5" {
		t.Errorf("version = %q, want 2.8.5", v)
	}
	if v := parseTimThumbVersion([]byte("<?php // no version define")); v != "" {
		t.Errorf("version = %q, want empty", v)
	}
}

func TestTimThumbVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"2.8.5", "2.8.14", true},
		{"2.8.14", "2.8.14", false},
		{"2.8.15", "2.8.14", false},
		{"3.0", "2.8.14", false},
		{"2.8", "2.8.14", true},
	}
	for _, c := range cases {
		if got := timThumbVersionLess(c.a, c.b); got != c.want {
			t.Errorf("timThumbVersionLess(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestAssessTimThumb(t *testing.T) {
	// Below the last-patched version -> High (known RCE).
	if sev, _ := assessTimThumb([]byte(timThumbHead)); sev != alert.High {
		t.Errorf("2.8.5 severity = %v, want High", sev)
	}
	// Patched-but-deprecated -> Warning.
	patched := []byte("<?php /* TimThumb */ define ('VERSION', '2.8.14');")
	if sev, _ := assessTimThumb(patched); sev != alert.Warning {
		t.Errorf("2.8.14 severity = %v, want Warning", sev)
	}
	// Unknown version cannot be confirmed patched -> High.
	unknown := []byte("<?php /* TimThumb */ define('BLOCK_EXTERNAL_LEECHERS', false);")
	if sev, _ := assessTimThumb(unknown); sev != alert.High {
		t.Errorf("unknown-version severity = %v, want High", sev)
	}
}

func TestScanForTimThumbWalk(t *testing.T) {
	docroot := t.TempDir()
	// Vulnerable TimThumb bundled deep in a theme.
	mustWriteFile(t, filepath.Join(docroot, "wp-content/themes/old2012/framework/scripts/timthumb.php"), timThumbHead)
	// A benign, unrelated thumb.php must not be flagged.
	mustWriteFile(t, filepath.Join(docroot, "wp-content/themes/modern/inc/thumb.php"), "<?php // theme helper\nfunction thumb(){}")
	// A patched TimThumb -> Warning, still reported.
	mustWriteFile(t, filepath.Join(docroot, "thumb.php"), "<?php /* TimThumb */ define ('VERSION', '2.8.14');")

	var findings []alert.Finding
	scanForTimThumb(context.Background(), docroot, 10, &findings)

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (vulnerable + patched TimThumb, not the benign helper): %+v", len(findings), findings)
	}
	var sawHigh, sawWarn bool
	for _, f := range findings {
		if f.Check != "vulnerable_timthumb" {
			t.Errorf("unexpected check %q", f.Check)
		}
		switch f.Severity {
		case alert.High:
			sawHigh = true
		case alert.Warning:
			sawWarn = true
		}
	}
	if !sawHigh || !sawWarn {
		t.Errorf("expected one High (2.8.5) and one Warning (2.8.14); high=%v warn=%v", sawHigh, sawWarn)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
