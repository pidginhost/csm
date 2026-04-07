package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// buildFakeTarGz creates a tar.gz containing a fake .mmdb file.
func buildFakeTarGz(edition string) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := []byte("fake-mmdb-for-" + edition)
	hdr := &tar.Header{
		Name: edition + "_20260330/" + edition + ".mmdb",
		Size: int64(len(content)),
		Mode: 0600,
	}
	_ = tw.WriteHeader(hdr)
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

func TestUpdateIntegration(t *testing.T) {
	tarData := buildFakeTarGz("GeoLite2-City")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "123" || pass != "key" {
			w.WriteHeader(401)
			return
		}

		w.Header().Set("Last-Modified", "Tue, 30 Mar 2026 00:00:00 GMT")

		if r.Method == "HEAD" {
			return
		}
		_, _ = w.Write(tarData)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()

	// Test: use updateEditionWithURL with the test server URL
	client := srv.Client()
	result := updateEditionWithURL(client, tmpDir, "123", "key", "GeoLite2-City", srv.URL+"/geoip/databases")
	if result.Status != "updated" {
		t.Fatalf("expected 'updated', got %q (err: %v)", result.Status, result.Err)
	}

	// Verify .mmdb was written
	mmdbPath := filepath.Join(tmpDir, "GeoLite2-City.mmdb")
	data, err := os.ReadFile(mmdbPath)
	if err != nil {
		t.Fatalf("mmdb not found: %v", err)
	}
	if string(data) != "fake-mmdb-for-GeoLite2-City" {
		t.Fatalf("unexpected content: %q", data)
	}

	// Verify Last-Modified marker
	marker, err := os.ReadFile(filepath.Join(tmpDir, ".last-modified-GeoLite2-City"))
	if err != nil {
		t.Fatalf("marker not found: %v", err)
	}
	if string(marker) != "Tue, 30 Mar 2026 00:00:00 GMT" {
		t.Fatalf("unexpected marker: %q", marker)
	}

	// Test: second call should return up_to_date
	result = updateEditionWithURL(client, tmpDir, "123", "key", "GeoLite2-City", srv.URL+"/geoip/databases")
	if result.Status != "up_to_date" {
		t.Fatalf("expected 'up_to_date' on second call, got %q (err: %v)", result.Status, result.Err)
	}
}

func TestUpdateIntegration_BadCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	client := srv.Client()
	result := updateEditionWithURL(client, tmpDir, "bad", "creds", "GeoLite2-City", srv.URL+"/geoip/databases")
	if result.Status != "error" {
		t.Fatalf("expected 'error', got %q", result.Status)
	}
	if result.Err == nil || result.Err.Error() != "invalid MaxMind credentials" {
		t.Fatalf("expected credentials error, got: %v", result.Err)
	}
}
