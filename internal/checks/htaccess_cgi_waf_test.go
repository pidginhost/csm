package checks

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Attacker enables Perl/CGI execution of an uploaded shell by mapping a
// non-standard extension to a CGI handler. Real case 2026-07-23 (ALFA
// webshell): AddHandler cgi-script .alfa + AddType application/x-httpd-cgi .alfa.
func TestDetectorCGIHandlerAbuseFlagsAddHandlerCustomExt(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "AddHandler cgi-script .alfa\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (AddHandler custom ext) = %d, want 1", got)
	}
}

func TestDetectorCGIHandlerAbuseFlagsAddTypeHttpdCGI(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "AddType application/x-httpd-cgi .alfa\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (AddType x-httpd-cgi) = %d, want 1", got)
	}
}

func TestDetectorCGIHandlerAbuseFlagsDirectoryWideHandlers(t *testing.T) {
	dir := t.TempDir()
	body := "SetHandler cgi-script\nForceType application/x-httpd-cgi\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 2 {
		t.Errorf("cgi_handler_abuse directory-wide matches = %d, want 2", got)
	}
}

func TestDetectorCGIHandlerAbuseFlagsPerlModuleExtension(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "AddHandler cgi-script .pm\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (.pm mapping) = %d, want 1", got)
	}
}

func TestDetectorCGIHandlerAbuseFlagsNonPlainExtension(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "AddHandler cgi-script .alfa+\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (non-plain extension) = %d, want 1", got)
	}
}

func TestDetectorCGIHandlerAbuseFlagsContinuedDirective(t *testing.T) {
	dir := t.TempDir()
	body := "keep\nAddHandler cgi-script \\\n.alfa\nend\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, ranges := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Fatalf("cgi_handler_abuse (continued directive) = %d, want 1", got)
	}
	if cleaned := string(applyRangeRemoval([]byte(body), ranges)); cleaned != "keep\nend\n" {
		t.Fatalf("cleaned = %q, want \"keep\\nend\\n\"", cleaned)
	}
}

// A real cgi-bin maps the conventional CGI extensions (.cgi/.pl); flagging
// those would be a false positive on legitimate Perl scripts.
func TestDetectorCGIHandlerAbuseSkipsConventionalCGIExts(t *testing.T) {
	dir := t.TempDir()
	body := "AddHandler cgi-script .cgi .pl\nAddHandler fcgid-script .fcgi\n"
	path := writeHtaccess(t, dir, "cgi-bin", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 0 {
		t.Errorf("cgi_handler_abuse fired on conventional CGI mapping = %d, want 0", got)
	}
}

func TestDetectorCGIHandlerAbuseSkipsConventionalFilesMatch(t *testing.T) {
	dir := t.TempDir()
	body := strings.Join([]string{
		"<FilesMatch \"^.*\\.(cgi|pl)$\">",
		"SetHandler cgi-script",
		"</FilesMatch>",
		"<Files\t~ \"\\.fcgi$\">",
		"SetHandler fcgid-script",
		"</Files>",
	}, "\n") + "\n"
	path := writeHtaccess(t, dir, "cgi-bin", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 0 {
		t.Errorf("cgi_handler_abuse fired on conventional FilesMatch = %d, want 0", got)
	}
}

func TestDetectorCGIHandlerAbuseFlagsBroadFilesMatchPatterns(t *testing.T) {
	dir := t.TempDir()
	body := strings.Join([]string{
		"<FilesMatch \"\\.cgi\">",
		"SetHandler cgi-script",
		"</FilesMatch>",
		"<FilesMatch \"^shell$|\\.pl$\">",
		"SetHandler cgi-script",
		"</FilesMatch>",
	}, "\n") + "\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 2 {
		t.Errorf("cgi_handler_abuse broad FilesMatch matches = %d, want 2", got)
	}
}

func TestDetectorCGIHandlerAbuseFlagsCustomFilesMatch(t *testing.T) {
	dir := t.TempDir()
	body := "<FilesMatch \"\\.alfa$\">\nSetHandler cgi-script\n</FilesMatch>\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (custom FilesMatch) = %d, want 1", got)
	}
}

func TestDetectorCGIHandlerAbuseRejectsHandlerNameSubstring(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "AddHandler not-cgi-script .alfa\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 0 {
		t.Errorf("cgi_handler_abuse fired on unrelated handler = %d, want 0", got)
	}
}

// The cleaner must be able to strip the malicious handler line.
func TestDetectorCGIHandlerAbuseCleans(t *testing.T) {
	dir := t.TempDir()
	body := "keep\nAddHandler cgi-script .alfa\nend\n"
	path := writeHtaccess(t, dir, "site", body)
	_, ranges := AuditHtaccessFile(path)
	cleaned := string(applyRangeRemoval([]byte(body), ranges))
	if cleaned != "keep\nend\n" {
		t.Fatalf("cleaned = %q, want \"keep\\nend\\n\"", cleaned)
	}
}

// Attacker disables the WAF from a per-account .htaccess to hide the
// intrusion. Real case 2026-07-23: an obfuscated `Sec------Engine Off`
// inside <IfModule mod_security.c>.
func TestDetectorSecurityDisabledFlagsStandardDirective(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "<IfModule mod_security.c>\nSecFilterEngine Off\n</IfModule>\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_security_disabled"); got != 1 {
		t.Errorf("security_disabled (SecFilterEngine Off) = %d, want 1", got)
	}
}

func TestDetectorSecurityDisabledFlagsObfuscatedVariant(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "Sec------Engine Off\nSec------ScanPOST Off\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_security_disabled"); got != 2 {
		t.Errorf("security_disabled obfuscated matches = %d, want 2", got)
	}
}

func TestDetectorSecurityDisabledFlagsDetectionOnly(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "SecRuleEngine DetectionOnly\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_security_disabled"); got != 1 {
		t.Errorf("security_disabled (SecRuleEngine DetectionOnly) = %d, want 1", got)
	}
}

func TestDetectorSecurityDisabledFlagsContinuedDirective(t *testing.T) {
	dir := t.TempDir()
	body := "keep\nSecRule\\\nEngine \\\nOff\nend\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, ranges := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_security_disabled"); got != 1 {
		t.Fatalf("security_disabled (continued directive) = %d, want 1", got)
	}
	if cleaned := string(applyRangeRemoval([]byte(body), ranges)); cleaned != "keep\nend\n" {
		t.Fatalf("cleaned = %q, want \"keep\\nend\\n\"", cleaned)
	}
}

// Turning the engine ON is a hardening action, not tampering.
func TestDetectorSecurityDisabledSkipsEngineOn(t *testing.T) {
	dir := t.TempDir()
	path := writeHtaccess(t, dir, "site", "SecRuleEngine On\n")
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_security_disabled"); got != 0 {
		t.Errorf("security_disabled fired on SecRuleEngine On = %d, want 0", got)
	}
}

func TestDetectorSecurityDisabledSkipsUnrelatedOffDirectives(t *testing.T) {
	dir := t.TempDir()
	body := strings.Join([]string{
		"SecAuditEngine Off",
		"SecResponseBodyAccess Off",
		"SecStatusEngine Off",
		"SecHashEngine Off",
	}, "\n") + "\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_security_disabled"); got != 0 {
		t.Errorf("security_disabled fired on unrelated Off directives = %d, want 0", got)
	}
}

func TestDetectorSecurityDisabledFlagsInspectionBypasses(t *testing.T) {
	dir := t.TempDir()
	body := strings.Join([]string{
		"SecRuleInheritance Off",
		"SecRequestBodyAccess Off",
		"SecFilterScanPOST Off",
	}, "\n") + "\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_security_disabled"); got != 3 {
		t.Errorf("security_disabled inspection bypasses = %d, want 3", got)
	}
}

func TestHtaccessDetectorRegistryIntegrations(t *testing.T) {
	for _, detector := range htaccessDetectors {
		t.Run(detector.Name, func(t *testing.T) {
			if _, ok := LookupCheck(detector.Name); !ok {
				t.Error("finding is missing from the check registry")
			}
			if !HasFix(detector.Name) {
				t.Error("finding does not advertise its cleaner")
			}
			if FixDescription(detector.Name, "", "/home/account/public_html/.htaccess") == "" {
				t.Error("finding does not describe its cleaner")
			}
			if !CanVerify(detector.Name) {
				t.Error("finding does not advertise its re-check")
			}
			if !isHtaccessHardenedFinding(detector.Name) {
				t.Error("finding does not route through automatic cleaning")
			}
			if !slices.Contains(runnerFindingNames["htaccess"], detector.Name) {
				t.Error("finding is not cleared after a successful .htaccess scan")
			}
			if !slices.Contains(runnerNamesForFinding(detector.Name), "htaccess") {
				t.Error("finding name does not map back to the .htaccess runner")
			}
		})
	}
}

func TestNewHtaccessDetectorsApplyAndAutoClean(t *testing.T) {
	root := t.TempDir()
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	root = resolvedRoot
	oldRoots := fixHtaccessAllowedRoots
	oldBackupRoot := htaccessBackupDirRoot
	fixHtaccessAllowedRoots = []string{root}
	htaccessBackupDirRoot = t.TempDir()
	t.Cleanup(func() {
		fixHtaccessAllowedRoots = oldRoots
		htaccessBackupDirRoot = oldBackupRoot
	})

	tests := []struct {
		name string
		body string
	}{
		{
			name: "htaccess_cgi_handler_abuse",
			body: "keep\nAddHandler cgi-script .alfa\nend\n",
		},
		{
			name: "htaccess_security_disabled",
			body: "keep\nSecRuleEngine Off\nend\n",
		},
	}
	cfg := &config.Config{}
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.CleanHtaccess = true

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeHtaccess(t, root, strings.TrimPrefix(tt.name, "htaccess_"), tt.body)
			result := ApplyFix(tt.name, "", "", path)
			if !result.Success {
				t.Fatalf("ApplyFix failed: %s", result.Error)
			}
			if got, err := os.ReadFile(path); err != nil {
				t.Fatal(err)
			} else if string(got) != "keep\nend\n" {
				t.Fatalf("ApplyFix cleaned content = %q, want %q", got, "keep\nend\n")
			}

			if err := os.WriteFile(path, []byte(tt.body), 0644); err != nil {
				t.Fatal(err)
			}
			actions := AutoCleanHtaccess(cfg, []alert.Finding{{
				Check:    tt.name,
				FilePath: path,
			}})
			if len(actions) != 1 {
				t.Fatalf("AutoCleanHtaccess actions = %d, want 1", len(actions))
			}
			if got, err := os.ReadFile(path); err != nil {
				t.Fatal(err)
			} else if string(got) != "keep\nend\n" {
				t.Fatalf("AutoCleanHtaccess content = %q, want %q", got, "keep\nend\n")
			}
			verified := VerifyFinding(tt.name, "", "", path)
			if !verified.Checked || !verified.Resolved {
				t.Fatalf("VerifyFinding after cleaning = %+v, want resolved", verified)
			}
		})
	}
}

// Wordfence/BuddyBoss/Magento "code execution protection" blocks map
// .php and friends to cgi-script but pair it with Options -ExecCGI, which
// disables CGI execution -- the mapping is inert hardening, not webshell
// arming. Real 2026-07-23 false positives that auto-remediation then edited
// out of legitimate customer files.
func TestDetectorCGIHandlerAbuseSkipsWordfenceExecCGIProtection(t *testing.T) {
	dir := t.TempDir()
	body := "# BEGIN Wordfence code execution protection\n" +
		"<IfModule mod_php7.c>\nphp_flag engine 0\n</IfModule>\n\n" +
		"AddHandler cgi-script .php .phtml .php3 .pl .py .jsp .asp .htm .shtml .sh .cgi\n" +
		"Options -ExecCGI\n" +
		"# END Wordfence code execution protection\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 0 {
		t.Errorf("cgi_handler_abuse (Wordfence -ExecCGI protection) = %d, want 0", got)
	}
}

func TestDetectorCGIHandlerAbuseSkipsMagentoDefaultHandler(t *testing.T) {
	dir := t.TempDir()
	body := "Options -Indexes\n<IfModule mod_php7.c>\nphp_flag engine 0\n</IfModule>\n" +
		"AddHandler cgi-script .php .pl .py .jsp .asp .htm .shtml .sh .cgi\n" +
		"Options -ExecCGI\n" +
		"<FilesMatch \".+\\.(ph(p[3457]?|t|tml)|[aj]sp|p[ly]|sh|cgi|shtml?|html?)$\">\n" +
		"SetHandler default-handler\n</FilesMatch>\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 0 {
		t.Errorf("cgi_handler_abuse (Magento default-handler + -ExecCGI) = %d, want 0", got)
	}
}

// An attacker who actually wants execution enables it: the neutralizer skip
// must not fire when ExecCGI is turned back on.
func TestDetectorCGIHandlerAbuseFlagsWhenExecCGIReEnabled(t *testing.T) {
	dir := t.TempDir()
	body := "AddHandler cgi-script .php .phtml\nOptions -ExecCGI\nOptions +ExecCGI\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (ExecCGI re-enabled) = %d, want 1", got)
	}
}

// Mapping .php to cgi-script with CGI execution enabled (no disabling Options)
// is the arming technique and must still be flagged.
func TestDetectorCGIHandlerAbuseFlagsExecCGIEnabledMapping(t *testing.T) {
	dir := t.TempDir()
	body := "AddHandler cgi-script .php .phtml\nOptions +ExecCGI\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (+ExecCGI mapping) = %d, want 1", got)
	}
}

// A commented-out -ExecCGI is not active and must not suppress a live mapping.
func TestDetectorCGIHandlerAbuseIgnoresCommentedExecCGI(t *testing.T) {
	dir := t.TempDir()
	body := "AddHandler cgi-script .php .phtml\n# Options -ExecCGI\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (commented -ExecCGI) = %d, want 1", got)
	}
}

// Real 2026-07-23 legacy-shop file: `Options All -Indexes` (All would enable
// ExecCGI) precedes the mapping, but a trailing `Options -ExecCGI` wins, so
// execution is off and the mapping is inert.
func TestDetectorCGIHandlerAbuseSkipsAllThenDisabledExecCGI(t *testing.T) {
	dir := t.TempDir()
	body := "Options All -Indexes\n<IfModule mod_php7.c>\nphp_flag engine 0\n</IfModule>\n" +
		"AddHandler cgi-script .php .pl .py .jsp .asp .htm .shtml .sh .cgi\n" +
		"Options -ExecCGI\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 0 {
		t.Errorf("cgi_handler_abuse (Options All then -ExecCGI) = %d, want 0", got)
	}
}

// But `Options All` after a `-ExecCGI` re-enables execution and must flag.
func TestDetectorCGIHandlerAbuseFlagsDisabledThenAllExecCGI(t *testing.T) {
	dir := t.TempDir()
	body := "AddHandler cgi-script .php\nOptions -ExecCGI\nOptions All -Indexes\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (Options All re-enables) = %d, want 1", got)
	}
}

func TestDetectorCGIHandlerAbuseHonorsAbsoluteOptionsReset(t *testing.T) {
	dir := t.TempDir()
	body := "AddHandler cgi-script .php\nOptions +ExecCGI\nOptions Indexes FollowSymLinks\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 0 {
		t.Errorf("cgi_handler_abuse (absolute Options reset) = %d, want 0", got)
	}
}

func TestDetectorCGIHandlerAbuseFlagsRunScriptsReEnable(t *testing.T) {
	dir := t.TempDir()
	body := "AddHandler cgi-script .alfa\nOptions -ExecCGI\nOptions +RunScripts\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (RunScripts re-enables ExecCGI) = %d, want 1", got)
	}
}

func TestDetectorCGIHandlerAbuseDoesNotTrustConditionalDisable(t *testing.T) {
	dir := t.TempDir()
	body := "AddHandler cgi-script .alfa\nOptions +ExecCGI\n" +
		"<IfModule !mod_cgi.c>\nOptions -ExecCGI\n</IfModule>\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (conditional -ExecCGI) = %d, want 1", got)
	}
}

func TestDetectorCGIHandlerAbuseFlagsConditionalReEnable(t *testing.T) {
	dir := t.TempDir()
	body := "AddHandler cgi-script .alfa\n" +
		"<If \"%{REQUEST_URI} =~ m#\\\\.alfa$#\">\nOptions +ExecCGI\n</If>\n" +
		"Options -ExecCGI\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (conditional +ExecCGI) = %d, want 1", got)
	}
}

func TestDetectorCGIHandlerAbuseSkipsFilesMatchUnderDirectoryDisable(t *testing.T) {
	dir := t.TempDir()
	body := "Options -ExecCGI\n<FilesMatch \"\\.alfa$\">\n" +
		"SetHandler cgi-script\n</FilesMatch>\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 0 {
		t.Errorf("cgi_handler_abuse (directory -ExecCGI with FilesMatch) = %d, want 0", got)
	}
}

func TestDetectorCGIHandlerAbuseRejectsMalformedOptionsNeutralizer(t *testing.T) {
	dir := t.TempDir()
	body := "AddHandler cgi-script .alfa\nOptions ExecCGI -ExecCGI\n"
	path := writeHtaccess(t, dir, "site", body)
	findings, _ := AuditHtaccessFile(path)
	if got := countByCheck(findings, "htaccess_cgi_handler_abuse"); got != 1 {
		t.Errorf("cgi_handler_abuse (malformed Options syntax) = %d, want 1", got)
	}
}
