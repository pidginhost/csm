package checks

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// SecFilterEngine / SecFilterScanPOST are mod_security 1.x directives. No
// supported server still reads them: on Apache with mod_security2, LiteSpeed,
// or Nginx they are inert text. Reporting them as "security disabled" at High
// put legacy shop and Magento .htaccess files from a decade ago on par with an
// attacker switching the WAF off, and -- worse -- the cleaner then edited those
// customer files to strip a line that does nothing.
//
// They stay visible as a Warning, because an attacker who plants one is telling
// on themselves, but they no longer claim the WAF was turned off and they are
// no longer removed from a customer's file.

func severityOf(t *testing.T, findings []alert.Finding, check string) alert.Severity {
	t.Helper()
	for _, f := range findings {
		if f.Check == check {
			return f.Severity
		}
	}
	t.Fatalf("no %s finding present", check)
	return alert.Warning
}

func TestLegacySecFilterIsWarningAndNotCleaned(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "<IfModule mod_security.c>\nSecFilterEngine Off\nSecFilterScanPOST Off\n</IfModule>\n")
	findings, ranges := AuditHtaccessFile(path)

	if got := countByCheck(findings, "htaccess_security_disabled"); got != 2 {
		t.Fatalf("legacy directives should still be reported, got %d findings, want 2", got)
	}
	if sev := severityOf(t, findings, "htaccess_security_disabled"); sev != alert.Warning {
		t.Errorf("legacy mod_security 1.x directive severity = %v, want Warning", sev)
	}
	if len(ranges) != 0 {
		t.Errorf("cleaner would edit a customer file to remove inert directives: %d ranges", len(ranges))
	}
}

func TestModSecurity2DisablerStaysHighAndIsCleaned(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "SecRuleEngine Off\n")
	findings, ranges := AuditHtaccessFile(path)

	if sev := severityOf(t, findings, "htaccess_security_disabled"); sev != alert.High {
		t.Errorf("SecRuleEngine Off severity = %v, want High", sev)
	}
	if len(ranges) == 0 {
		t.Error("a live WAF disabler must still be cleanable")
	}
}

// A file carrying both must not have the live disabler masked by the legacy one.
func TestMixedLegacyAndLiveDisablerCleansOnlyTheLiveOne(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "SecFilterEngine Off\nSecRuleEngine Off\n")
	findings, ranges := AuditHtaccessFile(path)

	if got := countByCheck(findings, "htaccess_security_disabled"); got != 2 {
		t.Fatalf("both directives should be reported, got %d", got)
	}
	var sawHigh bool
	for _, f := range findings {
		if f.Check == "htaccess_security_disabled" && f.Severity == alert.High {
			sawHigh = true
			if !strings.Contains(f.Details, "SecRuleEngine") {
				t.Errorf("High finding should be the live disabler, details: %s", f.Details)
			}
		}
	}
	if !sawHigh {
		t.Error("live WAF disabler lost its High severity when a legacy directive was present")
	}
	if len(ranges) != 1 {
		t.Errorf("cleaner ranges = %d, want 1 (only the live disabler)", len(ranges))
	}
}

// Obfuscated spellings of the live directives are still treated as live.
func TestObfuscatedLiveDisablerStaysHigh(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "Sec------Engine Off\n")
	findings, ranges := AuditHtaccessFile(path)
	if sev := severityOf(t, findings, "htaccess_security_disabled"); sev != alert.High {
		t.Errorf("obfuscated SecRuleEngine severity = %v, want High", sev)
	}
	if len(ranges) == 0 {
		t.Error("obfuscated live disabler must still be cleanable")
	}
}
