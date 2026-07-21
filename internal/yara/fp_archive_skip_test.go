//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"testing"
)

// Raw-byte scanning of compressed containers finds spurious tokens in stored
// entries and filenames. The real payload is scanned when the archive is
// extracted to disk, so the scanner treats raw archive content as non-scannable.
func TestArchiveContentIsNotScanned(t *testing.T) {
	s := loadRepoYaraScanner(t)

	// Each archive magic, followed by bytes that would otherwise trip rules.
	payload := []byte("<?php eval($_POST['x']); system($_GET['c']); // c99shell b374k AnonymousFox")
	for _, tt := range []struct {
		name  string
		magic []byte
	}{
		{name: "zip", magic: []byte{'P', 'K', 0x03, 0x04}},
		{name: "zip_empty", magic: []byte{'P', 'K', 0x05, 0x06}},
		{name: "zip_descriptor", magic: []byte{'P', 'K', 0x07, 0x08}},
		{name: "gzip", magic: []byte{0x1f, 0x8b, 0x08, 0x00}},
		{name: "bzip2", magic: []byte{'B', 'Z', 'h', '9'}},
		{name: "xz", magic: []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}},
		{name: "7z", magic: []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}},
		{name: "rar4", magic: []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00}},
		{name: "rar5", magic: []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0x00}},
	} {
		buf := append(append([]byte{}, tt.magic...), payload...)
		hits, err := s.ScanBytesChecked(buf)
		if err != nil {
			t.Fatalf("%s archive scan: %v", tt.name, err)
		}
		if len(hits) > 0 {
			t.Errorf("%s archive: expected no matches, got %v", tt.name, ruleNames(hits))
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
