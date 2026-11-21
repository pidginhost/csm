package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCleanTarget(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
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
