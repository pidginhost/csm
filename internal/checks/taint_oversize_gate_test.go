package checks

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/jstaint"
	"github.com/pidginhost/csm/internal/phptaint"
)

// TestOversizeGapRejectsBinaryFiles covers the case
// TestOversizeGapRequiresPHPLookingContent missed: its fixtures were all
// text, and text without a PHP tag was already rejected. Media files are
// the ones that carried a chance open tag and flooded the coverage
// report.
func TestOversizeGapRejectsBinaryFiles(t *testing.T) {
	dir := t.TempDir()

	png := filepath.Join(dir, "photo.png")
	pngBytes := append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d},
		[]byte("IHDR\x00\x01<?php\x00pixels")...)
	if err := os.WriteFile(png, pngBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := filepath.Join(dir, "ro_RO.mo")
	if err := os.WriteFile(catalog, append([]byte{0xde, 0x12, 0x04, 0x95, 0x00, 0x00, 0x00, 0x00}, []byte("msgid<?msgstr")...), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(script, []byte("document.addEventListener('keydown', e => fetch('/x'));\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "big.php")
	if err := os.WriteFile(source, []byte("<?php\n$x = $_GET['a'];\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stat := func(path string) os.FileInfo {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}

	if phpFileMayBePHP(png, stat(png)) {
		t.Error("a PNG carrying a chance open tag was reported as PHP coverage")
	}
	if phpFileMayBePHP(catalog, stat(catalog)) {
		t.Error("a gettext catalog was reported as PHP coverage")
	}
	if !phpFileMayBePHP(source, stat(source)) {
		t.Error("a PHP source file was dropped from coverage")
	}

	if jsFileMayBeJS(png, stat(png)) {
		t.Error("a PNG was reported as JavaScript coverage")
	}
	if jsFileMayBeJS(catalog, stat(catalog)) {
		t.Error("a gettext catalog was reported as JavaScript coverage")
	}
	if !jsFileMayBeJS(script, stat(script)) {
		t.Error("a script file was dropped from coverage")
	}
	// Unreadable answers yes for both: a file the scan could not examine
	// is exactly what the coverage report exists to name.
	if !jsFileMayBeJS(filepath.Join(dir, "does-not-exist"), nil) {
		t.Error("an unreadable file was silently dropped from JavaScript coverage")
	}
}

// The gate has to hold in the walk itself, not just in the helper: the
// JS oversize branch recorded every file it saw, so a host's media and
// archives arrived as "JavaScript we failed to examine".
func TestOversizeJSGapSkipsBinaryFilesInTheWalk(t *testing.T) {
	useRollingStore(t)
	root := t.TempDir()

	// A PNG header followed by NUL padding past the analyzer's limit.
	png := filepath.Join(root, "photo.png")
	if err := os.WriteFile(png, []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(png, int64(jstaint.MaxSourceBytes)+1); err != nil {
		t.Fatal(err)
	}

	// Real text past the same limit.
	script := filepath.Join(root, "bundle.js")
	line := []byte("var a = 1;\n")
	if err := os.WriteFile(script, bytes.Repeat(line, (jstaint.MaxSourceBytes/len(line))+64), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := CheckYARADeep(context.Background(), &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{"yara_deep", logicalOwnerPHPTaintDeep},
	}, nil)

	gaps := jsFindingsByCheck(findings, "js_taint_scan_incomplete")
	if len(gaps) != 1 {
		t.Fatalf("js_taint_scan_incomplete findings = %d, want 1: %+v", len(gaps), findings)
	}
	reported := gaps[0].Message + "\n" + gaps[0].Details
	if strings.Contains(reported, "photo.png") {
		t.Errorf("a PNG was reported as JavaScript we failed to examine: %q", reported)
	}
	if !strings.Contains(reported, "bundle.js") {
		t.Errorf("an oversize script was dropped from the coverage report: %q", reported)
	}
	if !strings.Contains(reported, "oversize=1") {
		t.Errorf("gap count did not settle at the one real skip: %q", reported)
	}
}

// The PHP oversize gate has always peeked at the file, and the peek costs
// an open. Past the soft deadline the walk is stopping and must do no
// further I/O. The existing soft-deadline test covers only the YARA and
// JS gates, because it never enables the PHP consumer, so this violation
// went unnoticed.
func TestOversizePHPGateDoesNotOpenPastTheSoftDeadline(t *testing.T) {
	useRollingStore(t)
	enablePHPTaintConsumer(t)
	root := t.TempDir()
	path := writeYARADeepFile(t, root, "oversize.dat", strings.Repeat("x", phptaint.MaxSourceBytes+1))

	base := time.Now().Add(time.Hour)
	clock := base
	counter := &openCountingOS{OS: realOS{}, opens: map[string]int{}}
	fs := &faultingYARADeepOS{OS: counter}
	fs.lstat = func(gotPath string) (os.FileInfo, error) {
		info, err := fs.OS.Lstat(gotPath)
		if gotPath == path {
			clock = clock.Add(2 * yaraDeepDeadlineMargin)
		}
		return info, err
	}
	withMockOS(t, fs)
	useYARADeepClock(t, &clock)

	ctx, cancel := context.WithDeadline(context.Background(), base.Add(yaraDeepDeadlineMargin+time.Minute))
	defer cancel()
	CheckYARADeep(ctx, &config.Config{
		AccountRoots:   []string{root},
		DisabledChecks: []string{"yara_deep", logicalOwnerJSTaintDeep},
	}, nil)

	if counter.opens[path] != 0 {
		t.Fatalf("PHP oversize gate opened the file %d time(s) after the soft deadline, want 0", counter.opens[path])
	}
}
