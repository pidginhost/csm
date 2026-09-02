package firewall

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The country CIDR download accepted any 200 body larger than ten bytes and
// installed it over the previous good file, so an HTML interstitial or a
// moved upstream path silently emptied a country set at the next restart.
// A file is installed only when it parses as a CIDR list.
func TestDownloadCIDRFileRejectsBodiesWithoutCIDRs(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "CN.cidr")
	const previous = "1.0.1.0/24\n1.0.2.0/23\n"
	if err := os.WriteFile(out, []byte(previous), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>Rate limit exceeded, try again later</body></html>\n"))
	}))
	defer srv.Close()

	if downloadCIDRFile(&http.Client{Timeout: 5 * time.Second}, srv.URL, out) {
		t.Fatal("HTML body accepted as a country CIDR list")
	}
	got, err := os.ReadFile(out)
	if err != nil || string(got) != previous {
		t.Fatalf("previous CIDR file replaced: %q (%v)", got, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestDownloadCIDRFileInstallsValidList(t *testing.T) {
	out := filepath.Join(t.TempDir(), "RO.cidr")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# comment\n5.2.128.0/17\n31.5.0.0/16\n"))
	}))
	defer srv.Close()
	if !downloadCIDRFile(&http.Client{Timeout: 5 * time.Second}, srv.URL, out) {
		t.Fatal("valid CIDR list rejected")
	}
	got, _ := os.ReadFile(out)
	if !strings.Contains(string(got), "5.2.128.0/17") {
		t.Fatalf("installed file = %q", got)
	}
}
