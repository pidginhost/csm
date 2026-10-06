package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// SecFilterEngine / SecFilterScanPOST are mod_security 1.x spellings, but they
// are not inert everywhere. LiteSpeed treats <IfModule mod_security.c> as
// present, its WAF accepts the 1.x syntax, and by default it lets .htaccess turn
// the engine off. LiteSpeed documents that Magento 2's stock block below
// disables ModSecurity for the site. They are therefore a WAF disable like
// SecRuleEngine Off: reported at High and removed by the cleaner, so a finding
// never pairs with a cleaner that refuses to act on it.

const magentoStockSecFilterBlock = "############################################\n" +
	"## disable POST processing to not break multiple image upload\n" +
	"\n" +
	"    <IfModule mod_security.c>\n" +
	"        SecFilterEngine Off\n" +
	"        SecFilterScanPOST Off\n" +
	"    </IfModule>\n"

const magentoStockSecFilterCleaned = "############################################\n" +
	"## disable POST processing to not break multiple image upload\n" +
	"\n" +
	"    <IfModule mod_security.c>\n" +
	"    </IfModule>\n"

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

func TestLegacySecFilterIsHighAndCleaned(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", magentoStockSecFilterBlock)
	findings, ranges := AuditHtaccessFile(path)

	if got := countByCheck(findings, "htaccess_security_disabled"); got != 2 {
		t.Fatalf("legacy directives reported = %d, want 2", got)
	}
	for _, f := range findings {
		if f.Check == "htaccess_security_disabled" && f.Severity != alert.High {
			t.Errorf("legacy directive severity = %v, want High: %s", f.Severity, f.Details)
		}
	}
	if got := string(applyRangeRemoval([]byte(magentoStockSecFilterBlock), ranges)); got != magentoStockSecFilterCleaned {
		t.Errorf("cleaned content = %q, want %q", got, magentoStockSecFilterCleaned)
	}
}

// The deep scan raises the finding, then auto-response hands it to the
// cleaner. Both entry points must remove the directives, and the re-check must
// then see the file as resolved; a refusal here is what left the finding open
// and re-dispatched on every cycle.
func TestLegacySecFilterFindingIsCleanedByFixAndAutoResponse(t *testing.T) {
	withSimulatedProcessSignal(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	oldRoots := fixHtaccessAllowedRoots
	oldBackupRoot := htaccessBackupDirRoot
	fixHtaccessAllowedRoots = []string{root}
	htaccessBackupDirRoot = t.TempDir()
	t.Cleanup(func() {
		fixHtaccessAllowedRoots = oldRoots
		htaccessBackupDirRoot = oldBackupRoot
	})
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanHtaccess = true
	path := writeHtaccess(t, root, "site", magentoStockSecFilterBlock)

	result := ApplyFix(context.Background(), "htaccess_security_disabled", "", "", path)
	if !result.Success {
		t.Fatalf("ApplyFix = %+v, want success", result)
	}
	if got, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if string(got) != magentoStockSecFilterCleaned {
		t.Fatalf("ApplyFix content = %q, want %q", got, magentoStockSecFilterCleaned)
	}

	if err := os.WriteFile(path, []byte(magentoStockSecFilterBlock), 0644); err != nil {
		t.Fatal(err)
	}
	actions := AutoCleanHtaccess(cfg, []alert.Finding{{Check: "htaccess_security_disabled", FilePath: path}})
	if len(actions) != 1 || !strings.HasPrefix(actions[0].Message, "AUTO-CLEAN: ") {
		t.Fatalf("AutoCleanHtaccess actions = %+v, want one AUTO-CLEAN", actions)
	}
	if got, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if string(got) != magentoStockSecFilterCleaned {
		t.Fatalf("AutoCleanHtaccess content = %q, want %q", got, magentoStockSecFilterCleaned)
	}
	if verified := VerifyFinding("htaccess_security_disabled", "", "", path); !verified.Checked || !verified.Resolved {
		t.Fatalf("VerifyFinding after cleaning = %+v, want resolved", verified)
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

// A file carrying both spellings loses both lines and reports both at High.
func TestMixedLegacyAndModernDisablersAreBothCleaned(t *testing.T) {
	dir := t.TempDir()
	body := "keep\nSecFilterEngine Off\nmiddle\nSecRuleEngine Off\nend\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, ranges := AuditHtaccessFile(path)

	if got := countByCheck(findings, "htaccess_security_disabled"); got != 2 {
		t.Fatalf("both directives should be reported, got %d", got)
	}
	for _, f := range findings {
		if f.Check == "htaccess_security_disabled" && f.Severity != alert.High {
			t.Errorf("severity = %v, want High: %s", f.Severity, f.Details)
		}
	}
	if got := string(applyRangeRemoval([]byte(body), ranges)); got != "keep\nmiddle\nend\n" {
		t.Errorf("cleaned content = %q, want %q", got, "keep\nmiddle\nend\n")
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
