package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- LookupWithRDAP / fetchRDAP ---------------------------------------
//
// fetchRDAP calls https://rdap.org/ip/{ip} via a fresh http.Client with
// Timeout set and nil Transport. Nil Transport means DefaultTransport is
// used, so we can intercept the request by swapping DefaultTransport.
// Tests in this package run sequentially so this is safe.

type rdapRoundTripper struct {
	status int
	body   []byte
}

func (r *rdapRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode:    r.status,
		Body:          rdBody{Reader: bytes.NewReader(r.body)},
		ContentLength: int64(len(r.body)),
		Header:        make(http.Header),
		Request:       req,
	}, nil
}

type rdBody struct{ *bytes.Reader }

func (rdBody) Close() error { return nil }

func swapGeoipTransport(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	orig := http.DefaultTransport
	http.DefaultTransport = rt
	t.Cleanup(func() { http.DefaultTransport = orig })
}

func TestLookupWithRDAPFetchesAndCaches(t *testing.T) {
	// Build an RDAP response that exercises the vcardArray path.
	rdap := map[string]any{
		"name":    "Cloudflare Network",
		"country": "US",
		"handle":  "NET-104-16-0-0-1",
		"entities": []map[string]any{
			{
				"roles": []string{"registrant"},
				"vcardArray": []any{
					"vcard",
					[]any{
						[]any{"version", map[string]any{}, "text", "4.0"},
						[]any{"fn", map[string]any{}, "text", "Cloudflare, Inc."},
					},
				},
			},
		},
	}
	body, _ := json.Marshal(rdap)
	swapGeoipTransport(t, &rdapRoundTripper{status: 200, body: body})

	db := &DB{rdapTTL: map[string]rdapCacheEntry{}}
	info := db.LookupWithRDAP("104.16.0.1")
	if info.RDAPName != "Cloudflare Network" {
		t.Errorf("RDAPName = %q, want Cloudflare Network", info.RDAPName)
	}
	if info.RDAPCountry != "US" {
		t.Errorf("RDAPCountry = %q, want US", info.RDAPCountry)
	}

	// Second call should hit the cache — swap to an error RoundTripper
	// to confirm no second fetch happens.
	swapGeoipTransport(t, &rdapRoundTripper{status: 500, body: nil})
	info2 := db.LookupWithRDAP("104.16.0.1")
	if info2.RDAPName != "Cloudflare Network" {
		t.Errorf("cached RDAPName lost: %q", info2.RDAPName)
	}
}

func TestLookupWithRDAPHTTPError(t *testing.T) {
	swapGeoipTransport(t, &rdapRoundTripper{status: 500, body: nil})
	db := &DB{rdapTTL: map[string]rdapCacheEntry{}}
	info := db.LookupWithRDAP("203.0.113.1")
	if info.RDAPName != "" || info.RDAPCountry != "" {
		t.Errorf("HTTP 500 should yield empty RDAP fields, got %+v", info)
	}
}

func TestLookupWithRDAPBadJSON(t *testing.T) {
	swapGeoipTransport(t, &rdapRoundTripper{status: 200, body: []byte("not json")})
	db := &DB{rdapTTL: map[string]rdapCacheEntry{}}
	info := db.LookupWithRDAP("203.0.113.2")
	if info.RDAPName != "" {
		t.Errorf("bad JSON should yield empty RDAP, got %q", info.RDAPName)
	}
}

func TestLookupWithRDAPCacheExpiry(t *testing.T) {
	db := &DB{rdapTTL: map[string]rdapCacheEntry{
		"192.0.2.1": {
			info:    Info{RDAPName: "OldOrg"},
			fetched: time.Now().Add(-25 * time.Hour), // expired
		},
	}}
	body, _ := json.Marshal(map[string]any{"name": "NewOrg", "country": "US"})
	swapGeoipTransport(t, &rdapRoundTripper{status: 200, body: body})

	info := db.LookupWithRDAP("192.0.2.1")
	if info.RDAPName != "NewOrg" {
		t.Errorf("expired cache should be re-fetched, got %q", info.RDAPName)
	}
}

// --- updateEditionWithURL error branches ------------------------------

func buildMMDBTarGz(t *testing.T, edition string) []byte {
	t.Helper()
	// We pack a minimal file that is NOT a real MMDB — updateEditionWithURL
	// will fail validation after extraction. For success tests we'd need
	// a real .mmdb which is too large for unit tests.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	content := []byte("not a real mmdb")
	_ = tw.WriteHeader(&tar.Header{
		Name: edition + "_20260411/" + edition + ".mmdb",
		Size: int64(len(content)),
		Mode: 0600,
	})
	_, _ = tw.Write(content)
	tw.Close()
	gw.Close()
	return buf.Bytes()
}

func TestUpdateEditionWithURL401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	res := updateEditionWithURL(
		srv.Client(), t.TempDir(),
		"acct", "key",
		"GeoLite2-City",
		srv.URL,
	)
	if res.Err == nil || !strings.Contains(res.Err.Error(), "invalid MaxMind credentials") {
		t.Errorf("401 should yield invalid credentials error, got %v", res.Err)
	}
}

func TestUpdateEditionWithURL429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	res := updateEditionWithURL(
		srv.Client(), t.TempDir(),
		"acct", "key",
		"GeoLite2-City",
		srv.URL,
	)
	if res.Err == nil || !strings.Contains(res.Err.Error(), "rate limited") {
		t.Errorf("429 should yield rate limited error, got %v", res.Err)
	}
}

func TestUpdateEditionWithURLUpToDate(t *testing.T) {
	// Write marker first.
	dir := t.TempDir()
	markerPath := filepath.Join(dir, ".last-modified-GeoLite2-City")
	if err := os.WriteFile(markerPath, []byte("Mon, 11 Apr 2026 00:00:00 GMT"), 0600); err != nil {
		t.Fatal(err)
	}
	// HEAD returns the same Last-Modified.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "Mon, 11 Apr 2026 00:00:00 GMT")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := updateEditionWithURL(
		srv.Client(), dir, "acct", "key", "GeoLite2-City", srv.URL,
	)
	if res.Status != "up_to_date" {
		t.Errorf("matching Last-Modified should yield up_to_date, got status=%q err=%v", res.Status, res.Err)
	}
}

func TestUpdateEditionWithURLExtractsThenFailsValidate(t *testing.T) {
	// HEAD returns a new Last-Modified to force GET, then the GET returns
	// a tar.gz containing an invalid .mmdb so validation fails. This
	// exercises the full GET → extract → validate path.
	dir := t.TempDir()
	payload := buildMMDBTarGz(t, "GeoLite2-City")
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == "HEAD" {
			w.Header().Set("Last-Modified", "Mon, 11 Apr 2026 00:00:00 GMT")
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	res := updateEditionWithURL(
		srv.Client(), dir, "acct", "key", "GeoLite2-City", srv.URL,
	)
	if res.Err == nil || !strings.Contains(res.Err.Error(), "validate") {
		t.Errorf("invalid MMDB should fail validation, got status=%q err=%v", res.Status, res.Err)
	}
	if callCount < 2 {
		t.Errorf("expected HEAD + GET (2 calls), got %d", callCount)
	}
}

func TestUpdateEditionWithURLHEADError(t *testing.T) {
	// Server drops connection immediately.
	srv := httptest.NewUnstartedServer(nil)
	srv.Listener.Close()

	client := &http.Client{Timeout: 1 * time.Second}
	res := updateEditionWithURL(
		client, t.TempDir(),
		"acct", "key",
		"GeoLite2-City",
		"http://127.0.0.1:1", // guaranteed-unreachable
	)
	if res.Err == nil {
		t.Fatal("HEAD dial failure should produce an error")
	}
}

// --- Update top-level credential handling -----------------------------

func TestUpdateCreatesDirOnFirstRun(t *testing.T) {
	// Fresh dir that doesn't yet exist.
	dir := filepath.Join(t.TempDir(), "new-geoip-dir")
	results := Update(dir, "acct", "key", []string{"GeoLite2-City"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// The dir should exist even though the network call will fail.
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("Update should create the directory, got stat err %v", err)
	}
	// The single edition result should be an error because no network
	// call can succeed against api.maxmind.com in a test runner.
	if results[0].Status == "updated" {
		t.Errorf("unexpected updated status without a real network")
	}
}

func TestUpdateMkdirFails(t *testing.T) {
	// Put a FILE at the dbDir path so MkdirAll fails.
	path := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	results := Update(path, "acct", "key", []string{"GeoLite2-City"})
	if len(results) != 1 || results[0].Status != "error" {
		t.Errorf("MkdirAll failure should yield error results, got %+v", results)
	}
}
