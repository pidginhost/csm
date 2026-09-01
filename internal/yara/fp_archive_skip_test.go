//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"testing"
)

// Raw-byte scanning of compressed containers finds spurious tokens in stored
// entries and filenames. The real payload is scanned when the archive is
// extracted to disk, so a file that is an archive by name and by magic is not
// presented to the rules. The engine itself has no such policy (the worker
// process only sees bytes); it lives at the ScanBytesChecked boundary.
func TestArchiveContentIsNotScanned(t *testing.T) {
	s := loadRepoYaraScanner(t)

	// Each archive magic, followed by bytes that would otherwise trip rules.
	payload := []byte("<?php eval($_POST['x']); system($_GET['c']); // c99shell b374k AnonymousFox")
	for _, tt := range []struct {
		name  string
		file  string
		magic []byte
	}{
		{name: "zip", file: "backup.zip", magic: []byte{'P', 'K', 0x03, 0x04}},
		{name: "zip_empty", file: "backup.zip", magic: []byte{'P', 'K', 0x05, 0x06}},
		{name: "zip_descriptor", file: "backup.zip", magic: []byte{'P', 'K', 0x07, 0x08}},
		{name: "gzip", file: "site.tar.gz", magic: []byte{0x1f, 0x8b, 0x08, 0x00}},
		{name: "bzip2", file: "site.tar.bz2", magic: []byte{'B', 'Z', 'h', '9'}},
		{name: "xz", file: "site.tar.xz", magic: []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}},
		{name: "7z", file: "backup.7z", magic: []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}},
		{name: "rar4", file: "backup.rar", magic: []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00}},
		{name: "rar5", file: "backup.rar", magic: []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}},
	} {
		buf := append(append([]byte{}, tt.magic...), payload...)
		hits, err := ScanBytesChecked(s, tt.file, buf)
		if err != nil {
			t.Fatalf("%s archive scan: %v", tt.name, err)
		}
		if len(hits) > 0 {
			t.Errorf("%s archive: expected no matches, got %v", tt.name, ruleNames(hits))
		}
		// The identical bytes under an executable name are a polyglot webshell.
		hits, err = ScanBytesChecked(s, "shell.php", buf)
		if err != nil {
			t.Fatalf("%s-prefixed php scan: %v", tt.name, err)
		}
		if len(hits) == 0 {
			t.Errorf("%s magic in front of a .php webshell suppressed every rule", tt.name)
		}
	}
}

func TestArchiveFileIsNotScanned(t *testing.T) {
	s := loadRepoYaraScanner(t)
	archive := append([]byte{'P', 'K', 0x03, 0x04}, []byte("<?php system($_POST['cmd']);")...)
	path := filepath.Join(t.TempDir(), "backup.zip")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := s.ScanFileChecked(path, len(archive)+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Matches) != 0 {
		t.Fatalf("checked file scan matched compressed archive: %v", ruleNames(result.Matches))
	}
	if matches := s.ScanFile(path, len(archive)+1); len(matches) != 0 {
		t.Fatalf("legacy file scan matched compressed archive: %v", ruleNames(matches))
	}
}

func TestArchiveLikePrefixesRemainScannable(t *testing.T) {
	s := loadRepoYaraScanner(t)
	payload := []byte("<?php system($_POST['cmd']);")
	for _, prefix := range [][]byte{
		{'P', 'K', 0x03, 'X'},
		{0xfd, '7', 'z', 'X', 'X', 0x00},
		{'7', 'z', 0xbc, 0xaf, 0x00, 0x00},
		[]byte("Rar! ordinary text"),
	} {
		hits, err := s.ScanBytesChecked(append(prefix, payload...))
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) == 0 {
			t.Errorf("near-magic prefix %x suppressed a real PHP webshell", prefix)
		}
	}
}

func TestRealPhpStillScannedAfterArchiveGuard(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte("<?php system($_POST['cmd']);")
	hits, err := s.ScanBytesChecked(mal)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 {
		t.Error("real PHP webshell was not detected after the archive guard")
	}

	// A PHAR's PHP stub executes before __HALT_COMPILER, so it must remain
	// scannable even though the bytes after the stub hold an archive.
	phar := []byte("<?php system($_POST['c']); __HALT_COMPILER();")
	hits, err = s.ScanBytesChecked(phar)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 {
		t.Error("PHAR-style PHP content should still be scanned")
	}

	// Tar is an uncompressed container, so its raw entries remain useful to
	// YARA. Keep the ustar marker at its format-defined offset.
	tar := make([]byte, 262)
	copy(tar[257:], "ustar")
	tar = append(tar, mal...)
	hits, err = s.ScanBytesChecked(tar)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 {
		t.Error("webshell content in an uncompressed tar should still be scanned")
	}
}

func ruleNames(m []Match) []string {
	out := make([]string, 0, len(m))
	for _, x := range m {
		out = append(out, x.RuleName)
	}
	return out
}
