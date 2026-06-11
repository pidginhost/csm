package firewall

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type geoIPRoundTripFunc func(*http.Request) (*http.Response, error)

func (f geoIPRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func geoIPTestClient(status int, body io.ReadCloser) *http.Client {
	return &http.Client{Transport: geoIPRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       body,
			Request:    req,
		}, nil
	})}
}

type geoIPTestResponse struct {
	status int
	body   string
}

func geoIPTestClientForURLs(responses map[string]geoIPTestResponse) *http.Client {
	return &http.Client{Transport: geoIPRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		response, ok := responses[req.URL.String()]
		if !ok {
			return nil, errors.New("unexpected URL: " + req.URL.String())
		}
		return &http.Response{
			StatusCode: response.status,
			Body:       io.NopCloser(strings.NewReader(response.body)),
			Request:    req,
		}, nil
	})}
}

type geoIPErrorAfterDataBody struct {
	data []byte
	read bool
}

func (b *geoIPErrorAfterDataBody) Read(p []byte) (int, error) {
	if b.read {
		return 0, errors.New("forced read failure")
	}
	b.read = true
	return copy(p, b.data), nil
}

func (b *geoIPErrorAfterDataBody) Close() error {
	return nil
}

func TestLookupIPMatch(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "US.cidr"), []byte("203.0.113.0/24\n198.51.100.0/24\n"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "DE.cidr"), []byte("192.0.2.0/24\n"), 0600)

	matches := LookupIP(dir, "203.0.113.5")
	if len(matches) != 1 || matches[0] != "US" {
		t.Errorf("got %v, want [US]", matches)
	}
}

func TestLookupIPNoMatch(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "US.cidr"), []byte("203.0.113.0/24\n"), 0600)

	matches := LookupIP(dir, "10.0.0.1")
	if len(matches) != 0 {
		t.Errorf("got %v, want empty", matches)
	}
}

func TestLookupIPInvalid(t *testing.T) {
	if got := LookupIP(t.TempDir(), "not-an-ip"); got != nil {
		t.Errorf("invalid IP should return nil, got %v", got)
	}
}

func TestLookupIPv6EmptyDir(t *testing.T) {
	if got := LookupIP(t.TempDir(), "2001:db8::1"); got != nil {
		t.Errorf("empty IPv6 country DB should return nil, got %v", got)
	}
}

func TestLookupIPEmptyDir(t *testing.T) {
	matches := LookupIP(t.TempDir(), "203.0.113.5")
	if len(matches) != 0 {
		t.Errorf("empty dir should return no matches, got %v", matches)
	}
}

func TestLookupIPMissingDir(t *testing.T) {
	matches := LookupIP(filepath.Join(t.TempDir(), "missing"), "203.0.113.5")
	if matches != nil {
		t.Errorf("missing dir should return nil, got %v", matches)
	}
}

func TestContainsIPSkipsComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.cidr")
	_ = os.WriteFile(path, []byte("# comment\n\n203.0.113.0/24\n"), 0600)

	ip := []byte{203, 0, 113, 5}
	if !containsIP(path, ip) {
		t.Error("should match after skipping comments")
	}
}

func TestUpdateGeoIPDBCountsEachRefreshedFamily(t *testing.T) {
	dir := t.TempDir()
	client := geoIPTestClientForURLs(map[string]geoIPTestResponse{
		geoIPBaseURL + "us.cidr":   {status: http.StatusOK, body: "203.0.113.0/24\n"},
		geoIPBaseURLv6 + "us.cidr": {status: http.StatusOK, body: "2001:db8::/32\n"},
		geoIPBaseURL + "de.cidr":   {status: http.StatusOK, body: "198.51.100.0/24\n"},
		geoIPBaseURLv6 + "de.cidr": {status: http.StatusNotFound, body: "not found\n"},
	})

	updated, err := updateGeoIPDBWithClient(dir, []string{"us", "DE", "bad"}, client)
	if err != nil {
		t.Fatalf("updateGeoIPDBWithClient: %v", err)
	}
	if updated != 3 {
		t.Fatalf("updated = %d, want 3 refreshed files", updated)
	}
	for _, name := range []string{"US.cidr", "US.cidr6", "DE.cidr"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s was not written: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "DE.cidr6")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("DE.cidr6 should not exist after failed IPv6 fetch: %v", err)
	}
}

func TestDownloadCIDRFileWritesOutput(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "US.cidr")
	body := "203.0.113.0/24\n"
	client := geoIPTestClient(http.StatusOK, io.NopCloser(strings.NewReader(body)))

	if !downloadCIDRFile(client, "https://example.test/us.cidr", outPath) {
		t.Fatal("downloadCIDRFile returned false")
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != body {
		t.Fatalf("output = %q, want %q", got, body)
	}
}

func TestDownloadCIDRFileRejectsCopyError(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "US.cidr")
	client := geoIPTestClient(http.StatusOK, &geoIPErrorAfterDataBody{data: []byte("203.0.113.0/24\n")})

	if downloadCIDRFile(client, "https://example.test/us.cidr", outPath) {
		t.Fatal("downloadCIDRFile returned true after body read failure")
	}
	if _, err := os.Stat(outPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("output exists after copy failure: %v", err)
	}
	if _, err := os.Stat(outPath + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp output exists after copy failure: %v", err)
	}
}

func TestDownloadCIDRFileRejectsRenameError(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "US.cidr")
	if err := os.Mkdir(outPath, 0700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	client := geoIPTestClient(http.StatusOK, io.NopCloser(strings.NewReader("203.0.113.0/24\n")))

	if downloadCIDRFile(client, "https://example.test/us.cidr", outPath) {
		t.Fatal("downloadCIDRFile returned true after rename failure")
	}
	if _, err := os.Stat(outPath + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp output exists after rename failure: %v", err)
	}
}
