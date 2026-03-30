package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateEmptyCredentials(t *testing.T) {
	results := Update("/tmp/geoip-test", "", "somekey", []string{"GeoLite2-City"})
	if results != nil {
		t.Fatalf("expected nil results for empty account_id, got %v", results)
	}

	results = Update("/tmp/geoip-test", "12345", "", []string{"GeoLite2-City"})
	if results != nil {
		t.Fatalf("expected nil results for empty license_key, got %v", results)
	}
}

func TestExtractMMDB(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := []byte("fake-mmdb-content-for-testing")
	hdr := &tar.Header{
		Name: "GeoLite2-City_20260328/GeoLite2-City.mmdb",
		Size: int64(len(content)),
		Mode: 0600,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gw.Close()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "GeoLite2-City.mmdb.tmp")

	err := extractMMDB(&buf, destPath, "GeoLite2-City")
	if err != nil {
		t.Fatalf("extractMMDB failed: %v", err)
	}

	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("reading extracted file: %v", err)
	}
	if string(got) != "fake-mmdb-content-for-testing" {
		t.Fatalf("content mismatch: got %q", got)
	}
}

func TestExtractMMDB_NoMMDB(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := []byte("not an mmdb")
	hdr := &tar.Header{
		Name: "GeoLite2-City_20260328/README.txt",
		Size: int64(len(content)),
		Mode: 0600,
	}
	tw.WriteHeader(hdr)
	tw.Write(content)
	tw.Close()
	gw.Close()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "GeoLite2-City.mmdb.tmp")

	err := extractMMDB(&buf, destPath, "GeoLite2-City")
	if err == nil {
		t.Fatal("expected error for archive with no .mmdb, got nil")
	}
}
