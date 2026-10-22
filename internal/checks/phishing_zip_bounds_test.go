package checks

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/zipdir"
)

// kitZipWithFiller puts evidence after the filler so detection must walk
// past every padding entry to reach it.
func kitZipWithFiller(t *testing.T, path string, filler int) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < filler; i++ {
		if _, err := zw.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("assets/%d.dat", i), Method: zip.Store}); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"office365/login.html", "office365/next.php", "office365/results.txt"} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(make([]byte, 500)); err != nil {
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

func TestPhishingZipUnreadDirectoryTailMarksIncomplete(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "style.css", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 1500)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	end := append([]byte(nil), buf.Bytes()[buf.Len()-zipdir.EndLen:]...)
	binary.LittleEndian.PutUint32(end[12:16], binary.LittleEndian.Uint32(end[12:16])+4)
	raw := append([]byte(nil), buf.Bytes()[:buf.Len()-zipdir.EndLen]...)
	raw = append(raw, []byte("junk")...)
	raw = append(raw, end...)
	ctx, collector := withIncompleteCheckCollector(context.Background())
	if phishingKitZipHasEvidence(ctx, bytes.NewReader(raw), int64(len(raw))) {
		t.Fatal("benign names reported as a kit")
	}
	if !collector.contains("phishing") {
		t.Fatal("unread directory bytes reported as a complete negative scan")
	}
}

// One byte appended after the end record must not hide a kit: unzip and PHP
// still open the file.
func TestPhishingKitWithTrailingByteStillDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "office365.zip")
	kitZipWithFiller(t, path, 0)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	ctx, c := withIncompleteCheckCollector(context.Background())
	if !zipLooksLikeKit(ctx, path) || c.contains("phishing") {
		t.Fatalf("kit with a trailing byte: detected=false or incomplete=%v", c.contains("phishing"))
	}
}
