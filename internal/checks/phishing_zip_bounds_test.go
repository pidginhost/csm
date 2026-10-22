package checks

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// kitZipWithFiller writes the three entries a real kit carries, then filler
// empty entries, padded past the scanner's 1000-byte gate.
func kitZipWithFiller(t *testing.T, path string, filler int) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range []string{"office365/login.html", "office365/next.php", "office365/results.txt"} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(make([]byte, 500)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < filler; i++ {
		if _, err := zw.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("assets/%d.dat", i), Method: zip.Store}); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Padding a kit with filler entries must not hide it: the whole listing is
// streamed one record at a time, so its size costs reading time, not memory.
func TestPhishingZipWithHugeListingStillDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "office365.zip")
	kitZipWithFiller(t, path, 30000)
	ctx, c := withIncompleteCheckCollector(context.Background())
	if !zipLooksLikeKit(ctx, path) {
		t.Fatal("a kit padded with filler entries was not detected")
	}
	if c.contains("phishing") {
		t.Fatal("a readable listing must not leave the check incomplete")
	}
}

func TestPhishingZipCancelledMidListMarksIncomplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "office365.zip")
	kitZipWithFiller(t, path, 5000)
	ctx, c := withIncompleteCheckCollector(context.Background())
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if zipLooksLikeKit(ctx, path) {
		t.Fatal("cancelled scan reported a kit")
	}
	if !c.contains("phishing") {
		t.Fatal("cancelled scan must mark the check incomplete")
	}
}
