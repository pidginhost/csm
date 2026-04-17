package wpcheck

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- DetectPluginRoot -----------------------------------------------------

func TestDetectPluginRoot_ParsesSlugFromPluginsPath(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		wantRoot string
		wantSlug string
	}{
		{
			name:     "main plugin file",
			path:     "/home/user/public_html/wp-content/plugins/wordfence/wordfence.php",
			wantRoot: "/home/user/public_html/wp-content/plugins/wordfence",
			wantSlug: "wordfence",
		},
		{
			name:     "nested file in plugin",
			path:     "/home/user/public_html/wp-content/plugins/wordfence/views/waf/waf-install.php",
			wantRoot: "/home/user/public_html/wp-content/plugins/wordfence",
			wantSlug: "wordfence",
		},
		{
			name:     "non-plugin path returns empty",
			path:     "/home/user/public_html/wp-content/uploads/hacked.php",
			wantRoot: "",
			wantSlug: "",
		},
		{
			name:     "plugins root itself returns empty",
			path:     "/home/user/public_html/wp-content/plugins/",
			wantRoot: "",
			wantSlug: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, slug := DetectPluginRoot(tc.path)
			if root != tc.wantRoot || slug != tc.wantSlug {
				t.Errorf("DetectPluginRoot(%q) = (%q, %q), want (%q, %q)",
					tc.path, root, slug, tc.wantRoot, tc.wantSlug)
			}
		})
	}
}

// --- ReadPluginVersion ----------------------------------------------------

func TestReadPluginVersion_ParsesHeaderFromMainFile(t *testing.T) {
	dir := t.TempDir()
	slug := "wordfence"
	pluginRoot := filepath.Join(dir, slug)
	if err := os.MkdirAll(pluginRoot, 0755); err != nil {
		t.Fatal(err)
	}
	header := `<?php
/*
Plugin Name: Wordfence Security - Firewall & Malware Scan
Plugin URI: http://www.wordfence.com/
Description: Protect WordPress from hacks and malware.
Version: 8.2.1
Author: Wordfence
License: GPLv2
*/
`
	if err := os.WriteFile(filepath.Join(pluginRoot, slug+".php"), []byte(header), 0644); err != nil {
		t.Fatal(err)
	}
	version, err := ReadPluginVersion(pluginRoot, slug)
	if err != nil {
		t.Fatalf("ReadPluginVersion: %v", err)
	}
	if version != "8.2.1" {
		t.Errorf("version = %q, want %q", version, "8.2.1")
	}
}

func TestReadPluginVersion_MissingMainFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadPluginVersion(dir, "nonexistent"); err == nil {
		t.Error("expected error for missing main plugin file")
	}
}

func TestReadPluginVersion_NoVersionHeaderReturnsError(t *testing.T) {
	dir := t.TempDir()
	slug := "broken"
	pluginRoot := filepath.Join(dir, slug)
	if err := os.MkdirAll(pluginRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginRoot, slug+".php"),
		[]byte(`<?php /* Plugin Name: Broken */`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPluginVersion(pluginRoot, slug); err == nil {
		t.Error("expected error when Version: header missing")
	}
}

// --- FetchPluginChecksums -------------------------------------------------

func TestFetchPluginChecksums_DownloadsZipAndHashesEntries(t *testing.T) {
	files := map[string][]byte{
		"test-plugin/test-plugin.php":     []byte("<?php // main\n"),
		"test-plugin/includes/helper.php": []byte("<?php // helper\n"),
		"test-plugin/assets/logo.svg":     []byte("<svg></svg>"),
	}
	zipBytes := buildPluginZip(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/test-plugin.1.2.3.zip") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()

	got, err := fetchPluginChecksumsFromURL(srv.URL+"/test-plugin.1.2.3.zip", "test-plugin")
	if err != nil {
		t.Fatalf("fetchPluginChecksumsFromURL: %v", err)
	}

	want := map[string]string{}
	for entry, data := range files {
		rel := strings.TrimPrefix(entry, "test-plugin/")
		h := sha256.Sum256(data)
		want[rel] = hex.EncodeToString(h[:])
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("hash mismatch for %q: got %q, want %q", k, got[k], v)
		}
	}
}

func buildPluginZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// --- Cache.IsVerifiedPluginFile ------------------------------------------

func TestIsVerifiedPluginFile_MatchesCachedHash(t *testing.T) {
	dir := t.TempDir()
	slug := "test-plugin"
	pluginRoot := filepath.Join(dir, "wp-content", "plugins", slug)
	if err := os.MkdirAll(pluginRoot, 0755); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(pluginRoot, slug+".php")
	body := []byte("<?php\n/*\nPlugin Name: Test\nVersion: 1.0.0\n*/\n")
	if err := os.WriteFile(main, body, 0644); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(body)
	want := hex.EncodeToString(h[:])

	c := NewCache(t.TempDir())
	c.setPluginChecksums(slug, "1.0.0", map[string]string{
		slug + ".php": want,
	})

	f, err := os.Open(main)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if !c.IsVerifiedPluginFile(int(f.Fd()), main) {
		t.Error("IsVerifiedPluginFile = false, want true for a file matching the cached hash")
	}
}

func TestIsVerifiedPluginFile_TamperedFileNotVerified(t *testing.T) {
	dir := t.TempDir()
	slug := "test-plugin"
	pluginRoot := filepath.Join(dir, "wp-content", "plugins", slug)
	if err := os.MkdirAll(pluginRoot, 0755); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(pluginRoot, slug+".php")
	originalBody := []byte("<?php\n/*\nPlugin Name: Test\nVersion: 1.0.0\n*/\n")
	tamperedBody := []byte("<?php system($_GET['c']); ?>")
	h := sha256.Sum256(originalBody)
	cachedHash := hex.EncodeToString(h[:])

	// File on disk differs from the cached good-hash.
	if err := os.WriteFile(main, tamperedBody, 0644); err != nil {
		t.Fatal(err)
	}
	c := NewCache(t.TempDir())
	c.setPluginChecksums(slug, "1.0.0", map[string]string{
		slug + ".php": cachedHash,
	})

	f, err := os.Open(main)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if c.IsVerifiedPluginFile(int(f.Fd()), main) {
		t.Error("IsVerifiedPluginFile = true, want false when on-disk content differs from cached hash (tamper detection)")
	}
}

func TestIsVerifiedPluginFile_NonPluginPathReturnsFalse(t *testing.T) {
	c := NewCache(t.TempDir())
	if c.IsVerifiedPluginFile(0, "/home/user/public_html/wp-content/uploads/x.php") {
		t.Error("IsVerifiedPluginFile = true for non-plugin path, want false")
	}
}

// --- Adversarial ZIP hardening -------------------------------------------

func TestFetchPluginChecksums_RejectsOversizedEntry(t *testing.T) {
	// Build a ZIP where one entry decompresses past the per-entry cap.
	// Use a small compressed payload that expands to more than
	// maxPluginZipBytes; the simplest way is storing (no compression) a
	// buffer larger than the cap. The HTTP body cap will trip first if
	// we send the whole thing, so we set Method=Deflate and provide a
	// highly compressible payload of a size that passes the 100 MB
	// compressed ceiling but expands past it.
	//
	// Simulation: directly craft a ZIP locally where we write entries of
	// size (maxPluginZipBytes + 1) uncompressed via Deflate so the
	// resulting ZIP is small but decompression would blow the limit.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{
		Name:   "evil-plugin/huge.bin",
		Method: zip.Deflate,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Highly compressible payload (all zeroes) of size maxPluginZipBytes+1.
	big := make([]byte, maxPluginZipBytes+1)
	if _, werr := w.Write(big); werr != nil {
		t.Fatal(werr)
	}
	if cerr := zw.Close(); cerr != nil {
		t.Fatal(cerr)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	_, err = fetchPluginChecksumsFromURL(srv.URL+"/evil-plugin.0.0.1.zip", "evil-plugin")
	if err == nil {
		t.Fatal("expected error for decompression-bomb entry, got nil")
	}
}

func TestFetchPluginChecksums_RejectsPathTraversalEntry(t *testing.T) {
	// Craft a ZIP whose entry uses ../ to escape the plugin root.
	files := map[string][]byte{
		"evil-plugin/evil-plugin.php":     []byte("<?php // main"),
		"evil-plugin/../../../etc/passwd": []byte("root:x:0:0"),
	}
	zipBytes := buildPluginZip(t, files)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()

	got, err := fetchPluginChecksumsFromURL(srv.URL+"/evil-plugin.0.0.1.zip", "evil-plugin")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	for k := range got {
		if strings.HasPrefix(k, "..") || strings.Contains(k, "/..") {
			t.Errorf("path-traversal entry leaked into checksum map: %q", k)
		}
	}
}
