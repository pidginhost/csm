//go:build linux

package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withAllowedRoots redirects all four package-level allowed-root lists to
// only `dir` for the duration of the test. Use this so success-path tests
// can write under t.TempDir() without modifying real /home or /tmp.
func withAllowedRoots(t *testing.T, dir string) {
	t.Helper()
	op := fixPermissionsAllowedRoots
	oq := fixQuarantineAllowedRoots
	oh := fixHtaccessAllowedRoots
	fixPermissionsAllowedRoots = []string{dir}
	fixQuarantineAllowedRoots = []string{dir}
	fixHtaccessAllowedRoots = []string{dir}
	t.Cleanup(func() {
		fixPermissionsAllowedRoots = op
		fixQuarantineAllowedRoots = oq
		fixHtaccessAllowedRoots = oh
	})
}

func withQuarantineDir(t *testing.T, dir string) {
	t.Helper()
	old := quarantineDir
	quarantineDir = dir
	t.Cleanup(func() { quarantineDir = old })
}

func withEximSpoolDirs(t *testing.T, dirs []string) {
	t.Helper()
	old := eximSpoolDirs
	eximSpoolDirs = dirs
	t.Cleanup(func() { eximSpoolDirs = old })
}

func TestFixPermissionsChmodsTo644(t *testing.T) {
	tmp := t.TempDir()
	withAllowedRoots(t, tmp)

	target := filepath.Join(tmp, "world.php")
	if err := os.WriteFile(target, []byte("<?php"), 0666); err != nil {
		t.Fatal(err)
	}

	res := fixPermissions(target)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("expected mode 0644, got %o", info.Mode().Perm())
	}
}

func TestFixPermissionsRejectsSymlink(t *testing.T) {
	tmp := t.TempDir()
	withAllowedRoots(t, tmp)

	target := filepath.Join(tmp, "real.php")
	if err := os.WriteFile(target, []byte("x"), 0666); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link.php")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	res := fixPermissions(link)
	if res.Success || !strings.Contains(res.Error, "symlinked") {
		t.Errorf("expected symlink rejection, got %+v", res)
	}
}

func TestFixQuarantineMovesRegularFile(t *testing.T) {
	tmp := t.TempDir()
	withAllowedRoots(t, tmp)
	qdir := filepath.Join(tmp, "quarantine")
	withQuarantineDir(t, qdir)

	src := filepath.Join(tmp, "evil.php")
	if err := os.WriteFile(src, []byte("malicious payload"), 0644); err != nil {
		t.Fatal(err)
	}

	res := fixQuarantine(src)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("source should be gone after quarantine, stat err=%v", err)
	}
	entries, err := os.ReadDir(qdir)
	if err != nil {
		t.Fatalf("read quarantine dir: %v", err)
	}
	hasFile, hasMeta := false, false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".meta") {
			hasMeta = true
		} else {
			hasFile = true
		}
	}
	if !hasFile || !hasMeta {
		t.Errorf("expected quarantined file + .meta sidecar, got %v", entries)
	}
}

func TestFixQuarantineRejectsSymlink(t *testing.T) {
	tmp := t.TempDir()
	withAllowedRoots(t, tmp)
	withQuarantineDir(t, filepath.Join(tmp, "q"))

	target := filepath.Join(tmp, "target.php")
	if err := os.WriteFile(target, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "link.php")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	res := fixQuarantine(link)
	if res.Success || !strings.Contains(res.Error, "symlinked") {
		t.Errorf("expected symlink rejection, got %+v", res)
	}
}

func TestFixHtaccessRemovesDangerousLines(t *testing.T) {
	tmp := t.TempDir()
	withAllowedRoots(t, tmp)

	htaccess := filepath.Join(tmp, ".htaccess")
	// Mix dangerous directives (auto_prepend_file, gzinflate) with safe ones
	// (Wordfence/LiteSpeed-style AddHandler/SetHandler) and a comment to
	// verify the cleaner preserves the safe lines and the comment.
	content := strings.Join([]string{
		"# Wordfence rules",
		"RewriteEngine On",
		"php_value auto_prepend_file /tmp/payload.php",
		"AddHandler application/x-httpd-php .php",
		"SetHandler application/x-httpd-alt-php74",
		"AddHandler text/html .html",
		"php_value foo gzinflate",
	}, "\n")
	if err := os.WriteFile(htaccess, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	res := fixHtaccess(htaccess, "htaccess injection at "+htaccess)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if !strings.Contains(res.Action, "removed") {
		t.Errorf("action should mention removal: %s", res.Action)
	}
	cleaned, err := os.ReadFile(htaccess)
	if err != nil {
		t.Fatal(err)
	}
	cs := string(cleaned)
	if strings.Contains(cs, "auto_prepend_file") {
		t.Errorf("auto_prepend_file should be stripped:\n%s", cs)
	}
	if strings.Contains(cs, "gzinflate") {
		t.Errorf("gzinflate should be stripped:\n%s", cs)
	}
	// Safe AddHandler/SetHandler lines must survive (whitelist matched).
	if !strings.Contains(cs, "application/x-httpd-php") {
		t.Errorf("safe AddHandler stripped:\n%s", cs)
	}
	if !strings.Contains(cs, "application/x-httpd-alt-php74") {
		t.Errorf("safe SetHandler stripped:\n%s", cs)
	}
	if !strings.Contains(cs, "# Wordfence") {
		t.Errorf("comment stripped:\n%s", cs)
	}
}

func TestFixHtaccessNoDangerousDirectivesReportsError(t *testing.T) {
	tmp := t.TempDir()
	withAllowedRoots(t, tmp)

	htaccess := filepath.Join(tmp, ".htaccess")
	clean := "# all good\nRewriteEngine On\nAddHandler application/x-httpd-php .php\n"
	if err := os.WriteFile(htaccess, []byte(clean), 0644); err != nil {
		t.Fatal(err)
	}

	res := fixHtaccess(htaccess, "msg")
	if res.Success || !strings.Contains(res.Error, "no malicious directives") {
		t.Errorf("expected nothing-to-remove error, got %+v", res)
	}
}

func TestFixQuarantineSpoolMessageMovesHandD(t *testing.T) {
	tmp := t.TempDir()
	spool := filepath.Join(tmp, "spool")
	if err := os.MkdirAll(spool, 0755); err != nil {
		t.Fatal(err)
	}
	withEximSpoolDirs(t, []string{spool})

	qdir := filepath.Join(tmp, "quarantine")
	withQuarantineDir(t, qdir)

	const msgID = "2jKPFm-000abc-1X"
	if err := os.WriteFile(filepath.Join(spool, msgID+"-H"), []byte("headers"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool, msgID+"-D"), []byte("body"), 0600); err != nil {
		t.Fatal(err)
	}

	res := fixQuarantineSpoolMessage("phishing (message: " + msgID + ")")
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}
	if !strings.Contains(res.Action, "2 files") {
		t.Errorf("action should report 2 files moved: %s", res.Action)
	}
	for _, suf := range []string{"-H", "-D"} {
		if _, err := os.Stat(filepath.Join(spool, msgID+suf)); !os.IsNotExist(err) {
			t.Errorf("spool %s should be removed, stat err=%v", suf, err)
		}
	}
	entries, _ := os.ReadDir(qdir)
	if len(entries) < 3 { // -H, -D, .meta
		t.Errorf("expected at least 3 quarantine entries (H/D/meta), got %d: %v", len(entries), entries)
	}
}
