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
	_ = tw.Close()
	_ = gw.Close()

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
	_ = tw.WriteHeader(hdr)
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gw.Close()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "GeoLite2-City.mmdb.tmp")

	err := extractMMDB(&buf, destPath, "GeoLite2-City")
	if err == nil {
		t.Fatal("expected error for archive with no .mmdb, got nil")
	}
}

func TestValidateMMDBRejectsInvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.mmdb")
	if err := os.WriteFile(path, []byte("not-a-valid-mmdb"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := validateMMDB(path); err == nil {
		t.Fatal("expected invalid mmdb to be rejected")
	}
}

// minimalMMDB is a valid MaxMind DB v2 file (204 bytes, ipv4, 1 node, record_size=24).
// Generated programmatically - opens successfully with maxminddb.Open().
var minimalMMDB = []byte{
	0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xab,
	0xcd, 0xef, 0x4d, 0x61, 0x78, 0x4d, 0x69, 0x6e, 0x64, 0x2e, 0x63, 0x6f,
	0x6d, 0xe8, 0x5b, 0x62, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x5f, 0x66, 0x6f,
	0x72, 0x6d, 0x61, 0x74, 0x5f, 0x6d, 0x61, 0x6a, 0x6f, 0x72, 0x5f, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0xa2, 0x00, 0x02, 0x5b, 0x62, 0x69,
	0x6e, 0x61, 0x72, 0x79, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x5f,
	0x6d, 0x69, 0x6e, 0x6f, 0x72, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0xa2, 0x00, 0x00, 0x4b, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x5f, 0x65,
	0x70, 0x6f, 0x63, 0x68, 0xc4, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x64, 0x61,
	0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x44,
	0x54, 0x65, 0x73, 0x74, 0x4b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0xe1, 0x42, 0x65, 0x6e, 0x44, 0x54, 0x65, 0x73,
	0x74, 0x4a, 0x69, 0x70, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0xa2, 0x00, 0x04, 0x4a, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x63, 0x6f, 0x75,
	0x6e, 0x74, 0xc4, 0x00, 0x00, 0x00, 0x01, 0x4b, 0x72, 0x65, 0x63, 0x6f,
	0x72, 0x64, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0xc4, 0x00, 0x00, 0x00, 0x18,
}

// writeTestMMDB writes the minimal valid MMDB to the given path.
func writeTestMMDB(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, minimalMMDB, 0600); err != nil {
		t.Fatalf("writing test mmdb: %v", err)
	}
}

func TestReload_NoFiles(t *testing.T) {
	tmpDir := t.TempDir()
	db := &DB{dbDir: tmpDir, rdapTTL: make(map[string]rdapCacheEntry)}
	err := db.Reload()
	if err == nil {
		t.Fatal("expected error when no .mmdb files exist, got nil")
	}
}

func TestReload_PreservesReadersOnFailure(t *testing.T) {
	// Start with a valid DB that has loaded readers
	tmpDir := t.TempDir()
	writeTestMMDB(t, filepath.Join(tmpDir, "GeoLite2-City.mmdb"))
	writeTestMMDB(t, filepath.Join(tmpDir, "GeoLite2-ASN.mmdb"))

	db := Open(tmpDir)
	if db == nil {
		t.Fatal("failed to open test DB")
	}
	if db.cityDB == nil || db.asnDB == nil {
		t.Fatal("expected both readers to be loaded")
	}
	defer db.Close()

	// Lookups should work (returns zero values but no error)
	info := db.Lookup("1.2.3.4")
	if info.IP != "1.2.3.4" {
		t.Fatalf("lookup returned wrong IP: %q", info.IP)
	}

	// Now remove the files to simulate a failed reload
	os.Remove(filepath.Join(tmpDir, "GeoLite2-City.mmdb"))
	os.Remove(filepath.Join(tmpDir, "GeoLite2-ASN.mmdb"))

	// Reload should return error but preserve old readers
	err := db.Reload()
	if err == nil {
		t.Fatal("expected error when files removed, got nil")
	}

	// Old readers must still be functional
	if db.cityDB == nil || db.asnDB == nil {
		t.Fatal("readers were nilled out after failed reload - safety guarantee violated")
	}

	// Lookups must still work with old readers
	info = db.Lookup("1.2.3.4")
	if info.IP != "1.2.3.4" {
		t.Fatalf("lookup broken after failed reload: %q", info.IP)
	}
}

func TestReload_PartialSuccess(t *testing.T) {
	// Start with both readers loaded
	tmpDir := t.TempDir()
	writeTestMMDB(t, filepath.Join(tmpDir, "GeoLite2-City.mmdb"))
	writeTestMMDB(t, filepath.Join(tmpDir, "GeoLite2-ASN.mmdb"))

	db := Open(tmpDir)
	if db == nil || db.cityDB == nil || db.asnDB == nil {
		t.Fatal("failed to open test DB with both readers")
	}
	defer db.Close()

	// Remove only the ASN file
	os.Remove(filepath.Join(tmpDir, "GeoLite2-ASN.mmdb"))

	// Reload should succeed (partial) - city reloaded, ASN preserved
	err := db.Reload()
	if err != nil {
		t.Fatalf("partial reload should succeed, got: %v", err)
	}

	// Both readers should still be non-nil
	if db.cityDB == nil {
		t.Fatal("cityDB is nil after partial reload")
	}
	if db.asnDB == nil {
		t.Fatal("asnDB was nilled out - old reader should be preserved")
	}
}

func TestOpenFresh_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	db := OpenFresh(tmpDir)
	if db != nil {
		t.Fatal("expected nil DB for empty directory")
	}
}
