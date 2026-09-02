package checks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func wpCoreCheckMocks(t *testing.T, wpOutput string) {
	t.Helper()
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "wp-config.php") {
				return []string{"/home/alice/public_html/wp-config.php"}, nil
			}
			return nil, nil
		},
	})
	withMockCmd(t, &mockCmd{
		runContext: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name == "wp" {
				return []byte(wpOutput), fmt.Errorf("exit status 1")
			}
			return nil, nil
		},
	})
}

func coreIntegrityFindings(findings []alert.Finding) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check == "wp_core_integrity" {
			out = append(out, f)
		}
	}
	return out
}

// A backdoor appended to a shipped core file is the most common core
// compromise, and wp-cli reports it as a checksum mismatch, not as an extra
// file. That line must become a finding that names the file.
func TestCheckWPCoreReportsModifiedCoreFile(t *testing.T) {
	wpCoreCheckMocks(t, "Warning: File doesn't verify against checksum: wp-includes/plugin.php\n"+
		"Error: WordPress installation doesn't verify against checksums.\n")

	got := coreIntegrityFindings(CheckWPCore(context.Background(), &config.Config{}, nil))
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if f.FilePath != "/home/alice/public_html/wp-includes/plugin.php" {
		t.Errorf("FilePath = %q, want the modified core file", f.FilePath)
	}
	if !strings.Contains(f.Details, "Path: /home/alice/public_html") {
		t.Errorf("Details must carry the install path for Re-check: %q", f.Details)
	}
}

// Critical drives auto-response, which kills processes and quarantines files.
// A core asset that PHP never executes cannot be the appended backdoor this
// check exists to catch, and on real hosts these mismatch for dull reasons: an
// SVG or CSS run through an optimiser, or an install whose version.php no
// longer matches the release its files came from. Those still deserve a
// finding, just not one that acts on its own.
func TestCheckWPCoreGradesNonExecutableCoreFilesBelowCritical(t *testing.T) {
	wpCoreCheckMocks(t, "Warning: File doesn't verify against checksum: wp-includes/js/mediaelement/controls.svg\n"+
		"Warning: File doesn't verify against checksum: wp-includes/css/dashicons.css\n"+
		"Warning: File doesn't verify against checksum: wp-includes/plugin.php\n")

	got := coreIntegrityFindings(CheckWPCore(context.Background(), &config.Config{}, nil))
	if len(got) != 3 {
		t.Fatalf("findings = %d, want 3: %+v", len(got), got)
	}
	bySeverity := map[string]alert.Severity{}
	for _, f := range got {
		bySeverity[f.FilePath] = f.Severity
	}
	for _, path := range []string{
		"/home/alice/public_html/wp-includes/js/mediaelement/controls.svg",
		"/home/alice/public_html/wp-includes/css/dashicons.css",
	} {
		if got := bySeverity[path]; got != alert.High {
			t.Errorf("severity for %s = %v, want High", path, got)
		}
	}
	if got := bySeverity["/home/alice/public_html/wp-includes/plugin.php"]; got != alert.Critical {
		t.Errorf("severity for the PHP core file = %v, want Critical", got)
	}
}

// A core .js file is not executed by PHP but is served to every visitor, so a
// skimmer spliced into one is exactly as reachable as a PHP backdoor.
func TestCheckWPCoreKeepsScriptCoreFilesCritical(t *testing.T) {
	wpCoreCheckMocks(t, "Warning: File doesn't verify against checksum: wp-includes/js/jquery/jquery.js\n")

	got := coreIntegrityFindings(CheckWPCore(context.Background(), &config.Config{}, nil))
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(got), got)
	}
	if got[0].Severity != alert.Critical {
		t.Errorf("severity = %v, want Critical for a served script", got[0].Severity)
	}
}

// Older wp-cli releases put the file name first.
func TestCheckWPCoreReportsModifiedCoreFileLegacyLineShape(t *testing.T) {
	wpCoreCheckMocks(t, "Warning: wp-includes/x.php doesn't verify against checksum.\n")

	got := coreIntegrityFindings(CheckWPCore(context.Background(), &config.Config{}, nil))
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(got), got)
	}
	if got[0].FilePath != "/home/alice/public_html/wp-includes/x.php" {
		t.Errorf("FilePath = %q, want the modified core file", got[0].FilePath)
	}
}

// Localised installs ship their own readme and license; those two root files
// are the documented noise and carry no code.
func TestCheckWPCoreIgnoresLocalizedReadmeAndLicense(t *testing.T) {
	wpCoreCheckMocks(t, "Warning: File doesn't verify against checksum: readme.html\n"+
		"Warning: File doesn't verify against checksum: license.txt\n")

	if got := coreIntegrityFindings(CheckWPCore(context.Background(), &config.Config{}, nil)); len(got) != 0 {
		t.Fatalf("readme/license noise produced findings: %+v", got)
	}
}

func TestCheckWPCoreModifiedFileNeverEscapesInstall(t *testing.T) {
	wpCoreCheckMocks(t, "Warning: File doesn't verify against checksum: ../../etc/passwd\n")

	got := coreIntegrityFindings(CheckWPCore(context.Background(), &config.Config{}, nil))
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1 (the line is still reported): %+v", len(got), got)
	}
	if got[0].FilePath != "" {
		t.Errorf("a relative path that escapes the install must not become a FilePath, got %q", got[0].FilePath)
	}
}

func TestVerifyWPCoreStillHasModifiedFileUnresolved(t *testing.T) {
	tmp := t.TempDir()
	withWPVerifyAllowedRoots(t, tmp)
	dir := makeWPInstall(t, tmp, "frank")
	wpCoreVerifyMock(t, []byte("Warning: File doesn't verify against checksum: wp-includes/plugin.php\n"), errors.New("exit status 1"))

	res := VerifyFinding("wp_core_integrity", "WordPress core file modified for frank", "Path: "+dir)
	if !res.Checked || res.Resolved {
		t.Fatalf("a still-modified core file must verify unresolved, got %+v", res)
	}
}
