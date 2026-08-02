package checks

import (
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
	sev, reasons := assessTimThumb(timThumbFile("2.8.14", "true", "false", "false"))
	if sev != alert.High {
		t.Errorf("external fetching enabled = %v, want High", sev)
	}
	if len(reasons) == 0 {
		t.Error("expected a reason to be reported")
	}
	sev, _ = assessTimThumb(timThumbFile("2.0", "FALSE", "false", "false"))
	if sev != alert.High {
		t.Errorf("outdated version = %v, want High", sev)
	}
}
