package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func writePHPTestFile(t *testing.T, root, rel string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), mode); err != nil {
		t.Fatal(err)
	}
}

func TestDetectPHPUnderFindsInterpreters(t *testing.T) {
	for _, rel := range []string{
		"usr/bin/php",
		"usr/bin/php8.3",
		"usr/sbin/php-fpm8.2",
		"opt/cpanel/ea-php83/root/usr/bin/php",
		"opt/alt/php81/usr/bin/php",
		"usr/local/lsws/lsphp83/bin/lsphp",
		"usr/local/lsws/fcgi-bin/lsphp",
		"opt/plesk/php/8.3/bin/php",
		"usr/local/php82/bin/php",
		"opt/remi/php83/root/usr/bin/php",
	} {
		t.Run(rel, func(t *testing.T) {
			root := t.TempDir()
			writePHPTestFile(t, root, rel, 0o755)
			if !detectPHPUnder(root) {
				t.Errorf("%s not detected", rel)
			}
		})
	}
}

func TestDetectPHPUnderIgnoresNonInterpreters(t *testing.T) {
	root := t.TempDir()
	// php-common helpers can outlive the interpreter.
	writePHPTestFile(t, root, "usr/sbin/phpenmod", 0o755)
	writePHPTestFile(t, root, "usr/sbin/phpdismod", 0o755)
	// A non-executable leftover is not an interpreter.
	writePHPTestFile(t, root, "usr/bin/php", 0o644)
	// Neither is a directory.
	if err := os.MkdirAll(filepath.Join(root, "usr/local/bin/php"), 0o755); err != nil {
		t.Fatal(err)
	}
	if detectPHPUnder(root) {
		t.Error("PHP reported on a host without an interpreter")
	}
}

func TestDetectPHPFallsBackToPath(t *testing.T) {
	orig := phpLookPath
	t.Cleanup(func() { phpLookPath = orig })

	phpLookPath = func(string) (string, error) { return "/srv/php/bin/php", nil }
	if !DetectPHP() {
		t.Error("php on PATH not detected")
	}
	if detectPHPUnder(t.TempDir()) {
		t.Error("empty root reported PHP")
	}
}
