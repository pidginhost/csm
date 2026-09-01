package yara

import "testing"

// recordingBackend counts how often the engine is actually asked to scan, so
// a test can tell a policy skip from a clean scan.
type recordingBackend struct {
	scans int
}

func (r *recordingBackend) ScanFile(string, int) []Match { return nil }
func (r *recordingBackend) ScanBytes([]byte) []Match {
	r.scans++
	return nil
}
func (r *recordingBackend) RuleCount() int { return 1 }
func (r *recordingBackend) Reload() error  { return nil }

// The archive skip exists because deflated bytes are not scannable and their
// stored filenames trip rules. That reasoning holds only for files that ARE
// archives; a .php file that merely begins with ZIP magic is executed by PHP
// with the magic echoed, so it must reach the engine.
func TestScanBytesCheckedSkipsArchivesOnlyByNameAndMagic(t *testing.T) {
	zipMagic := []byte{'P', 'K', 0x03, 0x04}
	shell := append(append([]byte{}, zipMagic...), []byte("<?php system($_POST['cmd']);")...)

	b := &recordingBackend{}
	if _, err := ScanBytesChecked(b, "/home/u/public_html/shell.php", shell); err != nil {
		t.Fatal(err)
	}
	if b.scans != 1 {
		t.Fatalf("zip-prefixed .php reached the engine %d times, want 1", b.scans)
	}

	b = &recordingBackend{}
	if _, err := ScanBytesChecked(b, "/home/u/backups/site.zip", zipMagic); err != nil {
		t.Fatal(err)
	}
	if b.scans != 0 {
		t.Fatalf("real .zip reached the engine %d times, want 0", b.scans)
	}

	b = &recordingBackend{}
	if _, err := ScanBytesChecked(b, "/home/u/public_html/cache/blob", zipMagic); err != nil {
		t.Fatal(err)
	}
	if b.scans != 1 {
		t.Fatalf("archive magic under a non-archive name reached the engine %d times, want 1", b.scans)
	}
}
