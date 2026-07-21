//go:build yara

package yara

import "testing"

// Post-deploy residual FP (2026-07-21): the deep scan matched YARA rules inside
// plugin backup .zip archives (wpvivid rollback) because raw-byte scanning of a
// compressed container finds spurious tokens in stored entries and filenames.
// The real payload is scanned when the archive is extracted to disk, so the
// scanner treats raw archive content as non-scannable.
func TestArchiveContentIsNotScanned(t *testing.T) {
	s := loadRepoYaraScanner(t)

	// Each archive magic, followed by bytes that would otherwise trip rules.
	payload := []byte("<?php eval($_POST['x']); system($_GET['c']); // c99shell b374k AnonymousFox")
	for name, magic := range map[string][]byte{
		"zip":   {'P', 'K', 0x03, 0x04},
		"zip_empty": {'P', 'K', 0x05, 0x06},
		"gzip":  {0x1f, 0x8b, 0x08, 0x00},
		"bzip2": {'B', 'Z', 'h', '9'},
		"xz":    {0xfd, '7', 'z', 'X', 'Z', 0x00},
		"7z":    {'7', 'z', 0xbc, 0xaf, 0x27, 0x1c},
		"rar":   {'R', 'a', 'r', '!', 0x1a, 0x07, 0x00},
	} {
		buf := append(append([]byte{}, magic...), payload...)
		if hits := s.ScanBytes(buf); len(hits) > 0 {
			t.Errorf("%s archive: expected no matches, got %v", name, ruleNames(hits))
		}
	}
}

func TestRealPhpStillScannedAfterArchiveGuard(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// A plain PHP webshell (no archive magic) must still be detected.
	mal := []byte("<?php system($_POST['cmd']);")
	if len(s.ScanBytes(mal)) == 0 {
		t.Error("real PHP webshell was not detected after the archive guard")
	}
	// A PHAR (executable PHP archive) starts with a php stub, not an archive
	// magic, so it stays scannable.
	phar := []byte("<?php // phar stub\n__HALT_COMPILER(); system($_POST['c']);")
	if len(s.ScanBytes(phar)) == 0 {
		t.Error("PHAR-style PHP content should still be scanned")
	}
}

func ruleNames(m []Match) []string {
	out := make([]string, 0, len(m))
	for _, x := range m {
		out = append(out, x.RuleName)
	}
	return out
}
