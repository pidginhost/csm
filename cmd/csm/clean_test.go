package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
)

func writeCleanTarget(t *testing.T, name, content string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertUnchanged(t *testing.T, path, content string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != content {
		t.Fatalf("%s changed: %q, %v", path, got, err)
	}
}

func TestRunCleanCommandPreviewWritesNothing(t *testing.T) {
	const infected = "<?php\n@include(\"/tmp/x\");\necho 'site';\n"
	path := writeCleanTarget(t, "index.php", infected)

	var stderr bytes.Buffer
	if code := runCleanCommand([]string{path, "--preview"}, &stderr); code != 0 {
		t.Fatalf("exit code = %d: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "\n-@include(\"/tmp/x\");\n") {
		t.Fatalf("preview does not show the removal:\n%s", stderr.String())
	}
	assertUnchanged(t, path, infected)
}

func TestRunCleanCommandFailsAnUnrenderablePreview(t *testing.T) {
	const infected = "<?php\n\x00\x0b@include(\"/tmp/x\");\necho 'site';\n"
	path := writeCleanTarget(t, "index.php", infected)

	var stderr bytes.Buffer
	if code := runCleanCommand([]string{"--preview", path}, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "binary") {
		t.Fatalf("failure does not say why: %s", stderr.String())
	}
	assertUnchanged(t, path, infected)
}

// The .htaccess cleaner acts only under account roots; the PHP cleaner would
// have read this file. Preview and apply must take the same cleaner.
func TestRunCleanCommandSendsHtaccessToItsCleaner(t *testing.T) {
	const body = "ErrorDocument 404 https://phish.example.tk/oops.html\n"
	path := writeCleanTarget(t, ".htaccess", body)

	for _, args := range [][]string{{path, "--preview"}, {path}} {
		var stderr bytes.Buffer
		if code := runCleanCommand(args, &stderr); code != 1 {
			t.Fatalf("%v: exit code = %d, want 1: %s", args, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "outside the allowed remediation roots") {
			t.Fatalf("%v: not the .htaccess cleaner's refusal: %s", args, stderr.String())
		}
		assertUnchanged(t, path, body)
	}
}

func TestRunCleanCommandEscapesTerminalControls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing\x1b[2J.php")

	var stderr bytes.Buffer
	if code := runCleanCommand([]string{path}, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if strings.ContainsRune(stderr.String(), '\x1b') || !strings.Contains(stderr.String(), `missing\x1b[2J.php`) {
		t.Fatalf("output not escaped: %q", stderr.String())
	}
}

func TestRunCleanCommandUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"--preview"}, {"/a.php", "/b.php"}} {
		var stderr bytes.Buffer
		if code := runCleanCommand(args, &stderr); code != 1 || !strings.Contains(stderr.String(), "Usage: csm clean <path> [--preview]") {
			t.Errorf("%v: exit code = %d, output %q", args, code, stderr.String())
		}
	}
}

func TestCleanPreviewEscapesMultilinePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing\nforged.php")
	var out bytes.Buffer
	if code := runCleanCommand([]string{path, "--preview"}, &out); code == 0 || strings.Contains(out.String(), "\nforged") {
		t.Fatalf("unsafe diagnostic %q", out.String())
	}
}

func TestCleanPreviewAcceptsRelativeHtaccess(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(checks.SetAccountHomeRootsForTest([]string{root}))
	site := filepath.Join(root, "site")
	if err := os.Mkdir(site, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(site)
	const body = "# keep\nAddHandler cgi-script .alfa\n"
	if err := os.WriteFile(".htaccess", []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := runCleanCommand([]string{".htaccess", "--preview"}, &out); code != 0 || !strings.Contains(out.String(), "\n-AddHandler cgi-script .alfa\n") {
		t.Fatalf("preview: %s", out.String())
	}
	assertUnchanged(t, ".htaccess", body)
}

func TestCleanPreviewUsesConfiguredContentRoot(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := writeCleanTarget(t, "csm.yaml", "account_roots:\n  - "+root+"\n")
	target := filepath.Join(root, ".htaccess")
	const body = "# keep\nAddHandler cgi-script .alfa\n"
	if err := os.WriteFile(target, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := runCleanCommand([]string{target, "--preview", "--config", cfg}, &out); code != 0 || !strings.Contains(out.String(), "\n-AddHandler cgi-script .alfa\n") {
		t.Fatalf("preview: %s", out.String())
	}
	assertUnchanged(t, target, body)
}

type failedPreviewWriter struct{}

func (failedPreviewWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestCleanPreviewReportsOutputFailure(t *testing.T) {
	const body = "<?php\n@include(\"/tmp/x\");\necho 'site';\n"
	path := writeCleanTarget(t, "site.php", body)
	if code := runCleanCommand([]string{path, "--preview"}, failedPreviewWriter{}); code == 0 {
		t.Fatal("reported success without delivering preview")
	}
	assertUnchanged(t, path, body)
}

func TestDBOptionPreviewRejectsUnknownFlags(t *testing.T) {
	for _, args := range [][]string{{"site", "widget_text", "--preview-only"}, {"site", "widget_text", "--preview=false"}, {"site", "widget_text", "extra"}} {
		called := false
		if code := runDBCleanOptionCommand(args, io.Discard, func(string, string, bool) checks.DBCleanResult {
			called = true
			return checks.DBCleanResult{Success: true}
		}); code == 0 || called {
			t.Fatalf("accepted %q", args)
		}
	}
	for _, args := range [][]string{{"--preview", "site", "widget_text"}, {"site", "widget_text", "--dry-run"}} {
		var called bool
		code := runDBCleanOptionCommand(args, io.Discard, func(account, option string, preview bool) checks.DBCleanResult {
			called = true
			if !preview || account != "site" || option != "widget_text" {
				t.Fatal("preview dispatched incorrectly")
			}
			return checks.DBCleanResult{Success: true}
		})
		if code != 0 || !called {
			t.Fatalf("refused %q", args)
		}
	}
}
