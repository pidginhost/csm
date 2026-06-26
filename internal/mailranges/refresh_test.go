package mailranges

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// resetMailrangesMetricsForTest resets the metrics atomics. Called by test
// cleanup so counter assertions start from a known-zero state.
func resetMailrangesMetricsForTest() {
	mailrangesRefreshTotal.Store(0)
	mailrangesPrefixes.Store(0)
	staleCacheWarnings.Store(0)
}

// resetRefreshState resets all package-level state touched by Refresh so
// tests do not bleed into each other. Reset happens immediately (so each test
// starts from a known-zero baseline for the metrics-not-bumped assertions) and
// again on cleanup.
func resetRefreshState(t *testing.T) {
	t.Helper()
	reset := func() {
		PublishProviderSnapshot(nil)
		lastRefreshAt.Store(0)
		resetMailrangesMetricsForTest()
	}
	reset()
	t.Cleanup(reset)
}

// seedSnapshot publishes a canned provider snapshot so tests can assert
// that a failed Refresh preserves the existing state.
func seedSnapshot(t *testing.T, cidrs map[string]string) {
	t.Helper()
	m := make(map[string][]*net.IPNet, len(cidrs))
	for provider, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("seedSnapshot: parse %q: %v", cidr, err)
		}
		m[provider] = []*net.IPNet{n}
	}
	PublishProviderSnapshot(m)
}

// TestRefresh_PartialFailureKeepsLastGood seeds google and microsoft, makes
// microsoft's SPF resolve fail, and asserts that google is updated while
// microsoft retains its last-good ranges and the cache file is written.
func TestRefresh_PartialFailureKeepsLastGood(t *testing.T) {
	resetRefreshState(t)

	// Seeded last-good overlay. These values are raw cache data and never flow
	// through ResolveSPF, so RFC 5737/3849 documentation prefixes are correct.
	seedSnapshot(t, map[string]string{
		"google":    "192.0.2.0/24",
		"microsoft": "198.51.100.0/24",
	})

	// Only Google's SPF root is in the resolver; microsoft's is absent -> fails.
	// Real public IPs are required in the TXT records here: they flow through
	// ResolveSPF, whose isPublicPrefix rejects RFC-doc prefixes on the collect
	// path. Do not swap these to RFC 5737/3849 ranges or the resolve will fail.
	r := mapResolver{
		"_spf.google.com": {"v=spf1 ip4:8.8.4.0/24 -all"},
	}

	cachePath := filepath.Join(t.TempDir(), "mailranges.json")
	total, err := Refresh(context.Background(), r, cachePath)

	// Partial failure: error must be non-nil (microsoft failed).
	if err == nil {
		t.Fatal("expected non-nil error for partial failure (microsoft failed)")
	}

	snap := ProviderSnapshot()

	// Google must be updated to the newly resolved public range.
	if len(snap["google"]) != 1 || snap["google"][0].String() != "8.8.4.0/24" {
		t.Errorf("google: got %v, want [8.8.4.0/24]", snap["google"])
	}

	// Microsoft must retain its previous (seeded, last-good) range.
	if len(snap["microsoft"]) != 1 || snap["microsoft"][0].String() != "198.51.100.0/24" {
		t.Errorf("microsoft: got %v, want [198.51.100.0/24]", snap["microsoft"])
	}

	// Cache file must have been written.
	if fi, statErr := os.Stat(cachePath); statErr != nil || fi.Size() == 0 {
		t.Errorf("cache file not written: stat err=%v", statErr)
	}

	// Total: google (1) + microsoft last-good (1).
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
}

// TestRefresh_AllFailuresKeepsOverlayAndReturnsError verifies that when every
// provider fails, the active snapshot is unchanged and a non-nil error is returned.
func TestRefresh_AllFailuresKeepsOverlayAndReturnsError(t *testing.T) {
	resetRefreshState(t)

	// Seeded last-good overlay (raw cache data; RFC-doc prefixes correct here).
	seedSnapshot(t, map[string]string{
		"google":    "192.0.2.0/24",
		"microsoft": "198.51.100.0/24",
	})

	// Empty resolver: every SPF lookup fails.
	r := mapResolver{}

	cachePath := filepath.Join(t.TempDir(), "mailranges.json")
	total, err := Refresh(context.Background(), r, cachePath)

	if err == nil {
		t.Fatal("expected non-nil error when all providers fail")
	}
	if total != 0 {
		t.Errorf("total = %d, want 0 on all-failure", total)
	}

	// Snapshot must not have changed.
	snap := ProviderSnapshot()
	if len(snap["google"]) != 1 || snap["google"][0].String() != "192.0.2.0/24" {
		t.Errorf("google overlay changed after all-failure: %v", snap["google"])
	}
	if len(snap["microsoft"]) != 1 || snap["microsoft"][0].String() != "198.51.100.0/24" {
		t.Errorf("microsoft overlay changed after all-failure: %v", snap["microsoft"])
	}

	// Cache file must NOT have been written.
	if _, statErr := os.Stat(cachePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("cache file must not be written on all-failure, stat err=%v", statErr)
	}

	// Metrics-only-on-success contract: no counter or gauge may move when every
	// provider fails. lastRefreshAt was reset to 0 and must stay there.
	if got := mailrangesRefreshTotal.Load(); got != 0 {
		t.Errorf("mailrangesRefreshTotal = %d, want 0 (no successful refresh)", got)
	}
	if got := mailrangesPrefixes.Load(); got != 0 {
		t.Errorf("mailrangesPrefixes = %d, want 0 (no successful refresh)", got)
	}
	if got := lastRefreshAt.Load(); got != 0 {
		t.Errorf("last_success_timestamp = %d, want 0 (unchanged)", got)
	}
}

// TestRefresh_CacheWriteFailureKeepsPreviousOverlay ensures that when the
// SPF resolver succeeds but the cache cannot be written (parent dir absent),
// the active snapshot is not updated and an error is returned.
func TestRefresh_CacheWriteFailureKeepsPreviousOverlay(t *testing.T) {
	resetRefreshState(t)

	// Seeded last-good overlay (raw cache data; RFC-doc prefixes correct here).
	seedSnapshot(t, map[string]string{
		"google":    "192.0.2.0/24",
		"microsoft": "198.51.100.0/24",
	})
	lastRefreshAt.Store(1000)

	// Both providers resolve to new ranges. Real public IPs required here: these
	// TXT records flow through ResolveSPF, which rejects RFC-doc prefixes.
	r := mapResolver{
		"_spf.google.com":            {"v=spf1 ip4:8.8.4.0/24 -all"},
		"spf.protection.outlook.com": {"v=spf1 ip4:1.1.1.0/24 -all"},
	}

	// cachePath whose parent directory does not exist -> write must fail.
	cachePath := filepath.Join(t.TempDir(), "nonexistent", "mailranges.json")

	total, err := Refresh(context.Background(), r, cachePath)

	if err == nil {
		t.Fatal("expected error when cache write fails")
	}
	if total != 0 {
		t.Errorf("total = %d, want 0 on cache write failure", total)
	}

	// Active snapshot must not have changed (still has old seeded ranges).
	snap := ProviderSnapshot()
	if len(snap["google"]) != 1 || snap["google"][0].String() != "192.0.2.0/24" {
		t.Errorf("google overlay changed after cache write failure: %v", snap["google"])
	}
	if len(snap["microsoft"]) != 1 || snap["microsoft"][0].String() != "198.51.100.0/24" {
		t.Errorf("microsoft overlay changed after cache write failure: %v", snap["microsoft"])
	}

	// Metrics-only-on-success contract: the write failed, so no counter/gauge
	// may move and last_success_timestamp must stay at its seeded value.
	if got := mailrangesRefreshTotal.Load(); got != 0 {
		t.Errorf("mailrangesRefreshTotal = %d, want 0 (write failed)", got)
	}
	if got := mailrangesPrefixes.Load(); got != 0 {
		t.Errorf("mailrangesPrefixes = %d, want 0 (write failed)", got)
	}
	if got := lastRefreshAt.Load(); got != 1000 {
		t.Errorf("last_success_timestamp = %d, want 1000 (unchanged after write failure)", got)
	}
}

// TestProvidersSourceListIsMailOnly asserts that the Providers map contains
// exactly the two mail-provider SPF roots and no forbidden source strings.
func TestProvidersSourceListIsMailOnly(t *testing.T) {
	wantRoots := map[string]string{
		"google":    "_spf.google.com",
		"microsoft": "spf.protection.outlook.com",
	}

	if len(Providers) != len(wantRoots) {
		t.Fatalf("Providers has %d entries, want %d", len(Providers), len(wantRoots))
	}

	for name, want := range wantRoots {
		got, ok := Providers[name]
		if !ok {
			t.Errorf("Providers missing key %q", name)
			continue
		}
		if got != want {
			t.Errorf("Providers[%q] = %q, want %q", name, got, want)
		}
	}

	forbidden := []string{"goog.json", "azure", "service-tag", "cloud", "asn", "cidr", "http://", "https://"}
	for name, root := range Providers {
		for _, bad := range forbidden {
			if strings.Contains(strings.ToLower(root), strings.ToLower(bad)) {
				t.Errorf("Providers[%q] = %q contains forbidden substring %q", name, root, bad)
			}
		}
	}
}

// TestRefresh_StaleCacheFailureWarns verifies that when all providers fail and
// the last successful refresh is more than 7 days old, the stale-cache warning
// counter is incremented.
func TestRefresh_StaleCacheFailureWarns(t *testing.T) {
	resetRefreshState(t)

	// Seeded last-good overlay (raw cache data; RFC-doc prefixes correct here).
	seedSnapshot(t, map[string]string{
		"google":    "192.0.2.0/24",
		"microsoft": "198.51.100.0/24",
	})

	// Set last refresh to 8 days ago (well past the 7-day threshold).
	stale := time.Now().Add(-8 * 24 * time.Hour).Unix()
	lastRefreshAt.Store(stale)

	// All providers fail.
	r := mapResolver{}

	cachePath := filepath.Join(t.TempDir(), "mailranges.json")
	_, err := Refresh(context.Background(), r, cachePath)
	if err == nil {
		t.Fatal("expected error on all-failure")
	}

	if staleCacheWarnings.Load() == 0 {
		t.Error("stale-cache warning not emitted when cache is >7 days old and all providers fail")
	}

	// Ranges must be preserved despite stale condition.
	snap := ProviderSnapshot()
	if len(snap["google"]) != 1 {
		t.Errorf("google ranges lost after stale-cache warning: %v", snap["google"])
	}
}

// TestGenerateSnapshot regenerates snapshot.json from live SPF records.
// Guarded by MAILRANGES_GENSNAPSHOT=1 so normal go test never hits the network.
func TestGenerateSnapshot(t *testing.T) {
	if os.Getenv("MAILRANGES_GENSNAPSHOT") == "" {
		t.Skip("set MAILRANGES_GENSNAPSHOT=1 to regenerate snapshot.json")
	}

	// CWD in go test is the package directory, so "snapshot.json" is the embed source.
	cachePath := "snapshot.json"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	total, err := Refresh(ctx, net.DefaultResolver, cachePath)
	if err != nil {
		t.Fatalf("Refresh with live resolver failed: %v", err)
	}
	t.Logf("snapshot.json regenerated: %d total prefixes", total)

	// Refresh writes compact JSON with no trailing newline. Append one so the
	// committed snapshot.json and any future regeneration produce byte-identical
	// files (the committed copy carries the same trailing newline).
	data, err := os.ReadFile(cachePath) // #nosec G304 -- package-local snapshot path
	if err != nil {
		t.Fatalf("read regenerated snapshot: %v", err)
	}
	if !bytes.HasSuffix(data, []byte("\n")) {
		data = append(data, '\n')
		if err := os.WriteFile(cachePath, data, 0o600); err != nil {
			t.Fatalf("rewrite snapshot with trailing newline: %v", err)
		}
	}

	snap := ProviderSnapshot()
	for name := range Providers {
		if len(snap[name]) == 0 {
			t.Errorf("provider %q has 0 prefixes after live refresh", name)
		}
		t.Logf("  %s: %d prefixes", name, len(snap[name]))
	}
}
