package checks

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A TimThumb copy on the final release with every remote-fetch and screenshot
// feature explicitly disabled has nothing an operator can act on. Reporting it
// every scan is noise that competes with real findings, so the mitigated case
// produces no finding at all. Anything short of that still reports.
func timThumbFile(version string, external, allExternal, webshot string) []byte {
	return []byte(`<?php
/**
 * TimThumb by Ben Gillbanks and Mark Maunder
 */
define ('VERSION', '` + version + `');
define ('ALLOW_EXTERNAL', ` + external + `);
define ('ALLOW_ALL_EXTERNAL_SITES', ` + allExternal + `);
define ('WEBSHOT_ENABLED', ` + webshot + `);
define ('FILE_CACHE_ENABLED', true);
`)
}

func TestTimThumbFinalVersionFullyDisabledIsMitigated(t *testing.T) {
	head := timThumbFile("2.8.14", "FALSE", "false", "false")
	if !timThumbMitigated(head) {
		t.Error("hardened final-version TimThumb should be treated as mitigated")
	}
}

func TestTimThumbStillReportedWhenRiskyFeatureEnabled(t *testing.T) {
	cases := map[string][]byte{
		"external fetching on":  timThumbFile("2.8.14", "true", "false", "false"),
		"all external sites on": timThumbFile("2.8.14", "FALSE", "true", "false"),
		"webshot on":            timThumbFile("2.8.14", "FALSE", "false", "true"),
	}
	for name, head := range cases {
		if timThumbMitigated(head) {
			t.Errorf("%s: must not be treated as mitigated", name)
		}
	}
}

func TestTimThumbMissingFeatureDefineIsNotMitigated(t *testing.T) {
	base := string(timThumbFile("2.8.14", "false", "false", "false"))
	for _, feature := range []string{timThumbExternal, timThumbAllExternal, timThumbWebshot} {
		line := "define ('" + feature + "', false);\n"
		head := []byte(strings.Replace(base, line, "", 1))
		if timThumbMitigated(head) {
			t.Errorf("missing %s define must not count as disabled", feature)
		}
	}
}

func TestTimThumbConflictingFeatureDefinesAreNotMitigated(t *testing.T) {
	head := append(timThumbFile("2.8.14", "false", "false", "false"),
		[]byte("define('ALLOW_EXTERNAL', true);\n")...)
	if timThumbMitigated(head) {
		t.Error("a true feature define must prevent mitigation even when a false define is also present")
	}
}

func TestTimThumbCommentedSafetyDefinesAreNotMitigated(t *testing.T) {
	head := []byte(`<?php
/* TimThumb */
define('VERSION', '2.8.14');
/*
define('ALLOW_EXTERNAL', false);
define('ALLOW_ALL_EXTERNAL_SITES', false);
define('WEBSHOT_ENABLED', false);
*/
`)
	if timThumbMitigated(head) {
		t.Error("commented-out feature defines are not evidence that TimThumb is disabled")
	}
}

func TestTimThumbMarkupSafetyDefinesAreNotMitigated(t *testing.T) {
	head := []byte(`<?php
/* TimThumb */
define('VERSION', '2.8.14');
?>
define('ALLOW_EXTERNAL', false);
define('ALLOW_ALL_EXTERNAL_SITES', false);
define('WEBSHOT_ENABLED', false);
`)
	if timThumbMitigated(head) {
		t.Error("define-like page text outside PHP is not evidence that TimThumb is disabled")
	}
}

func TestTimThumbStringSafetyDefinesAreNotMitigated(t *testing.T) {
	const defines = `define('ALLOW_EXTERNAL', false);
define('ALLOW_ALL_EXTERNAL_SITES', false);
define('WEBSHOT_ENABLED', false);`
	for name, literal := range map[string]string{
		"quoted string": `$documentation = "` + defines + `";`,
		"heredoc":       "$documentation = <<<'DOC'\n" + defines + "\nDOC;",
		"shell string":  "$documentation = `" + defines + "`;",
	} {
		head := []byte("<?php\n/* TimThumb */\ndefine('VERSION', '2.8.14');\n" + literal)
		if timThumbMitigated(head) {
			t.Errorf("%s define-like text is not evidence that TimThumb is disabled", name)
		}
	}
}

func TestTimThumbCommentedFinalVersionDoesNotHideOldRelease(t *testing.T) {
	body := strings.TrimPrefix(string(timThumbFile("2.8.13", "false", "false", "false")), "<?php\n")
	head := []byte("<?php // define('VERSION', '2.8.14');\n" + body)
	if timThumbMitigated(head) {
		t.Error("a final-version string in a comment must not hide an active older version")
	}
}

// An older release carries CVE-2011-4106 regardless of how the feature flags are
// set, so it is never mitigated.
func TestTimThumbOldVersionNeverMitigated(t *testing.T) {
	for _, v := range []string{"2.8.13", "2.0", "1.34"} {
		if timThumbMitigated(timThumbFile(v, "FALSE", "false", "false")) {
			t.Errorf("version %s must not be treated as mitigated", v)
		}
	}
	// an unreadable version is not evidence of safety
	if timThumbMitigated([]byte("<?php // timthumb\ndefine('ALLOW_EXTERNAL', false);\n")) {
		t.Error("missing version must not be treated as mitigated")
	}
}

// Severity for the cases that still report must not change.
func TestTimThumbSeverityUnchangedForReportedCases(t *testing.T) {
	for name, tc := range map[string]struct {
		head []byte
		want alert.Severity
	}{
		"external fetching":  {timThumbFile("2.8.14", "true", "false", "false"), alert.High},
		"all external sites": {timThumbFile("2.8.14", "false", "true", "false"), alert.Warning},
		"webshot":            {timThumbFile("2.8.14", "false", "false", "true"), alert.High},
		"outdated version":   {timThumbFile("2.0", "false", "false", "false"), alert.High},
	} {
		sev, reasons := assessTimThumb(tc.head)
		if sev != tc.want {
			t.Errorf("%s severity = %v, want %v", name, sev, tc.want)
		}
		if len(reasons) == 0 {
			t.Errorf("%s: expected a reason to be reported", name)
		}
	}
}

func TestScanForTimThumbSuppressesOnlyFullyMitigatedCopy(t *testing.T) {
	docroot := t.TempDir()
	mustWriteFile(t, filepath.Join(docroot, "safe", "timthumb.php"),
		string(timThumbFile("2.8.14", "false", "false", "false")))
	mustWriteFile(t, filepath.Join(docroot, "enabled", "timthumb.php"),
		string(timThumbFile("2.8.14", "true", "false", "false")))

	var findings []alert.Finding
	scanForTimThumb(context.Background(), docroot, 10, &findings)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want only the enabled copy: %+v", len(findings), findings)
	}
	if findings[0].Severity != alert.High || findings[0].FilePath != filepath.Join(docroot, "enabled", "timthumb.php") {
		t.Errorf("enabled copy finding = %+v, want the enabled path at High severity", findings[0])
	}
}
