package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLookupUserHitAndCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwd")
	if err := os.WriteFile(path, []byte("alice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cache := newUIDCache(path)
	if got := cache.Lookup(1000); got != "alice" {
		t.Fatalf("uid 1000 = %q, want alice", got)
	}
	if got := cache.Lookup(1001); got != "bob" {
		t.Fatalf("uid 1001 = %q, want bob", got)
	}
	// Mutate the file underneath: cache should still return the old value
	// (caching is process-lifetime; use cache.Refresh() to drop entries).
	if err := os.WriteFile(path, []byte("nobody:x:65534:65534::/:/usr/sbin/nologin\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := cache.Lookup(1000); got != "alice" {
		t.Fatalf("post-mutation uid 1000 = %q, want cached alice", got)
	}
}

func TestLookupUserMissReturnsUIDString(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwd")
	if err := os.WriteFile(path, []byte("alice:x:1000:1000::/home/alice:/bin/bash\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cache := newUIDCache(path)
	if got := cache.Lookup(9999); got != "uid:9999" {
		t.Fatalf("missing uid = %q, want uid:9999", got)
	}
}

func TestLookupUserMalformedLineSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwd")
	if err := os.WriteFile(path, []byte("garbage line no colons\nalice:x:1000:1000::/h:/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cache := newUIDCache(path)
	if got := cache.Lookup(1000); got != "alice" {
		t.Fatalf("uid 1000 = %q, want alice", got)
	}
}

func TestLookupUserRefreshRereads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwd")
	if err := os.WriteFile(path, []byte("alice:x:1000:1000::/home/alice:/bin/bash\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cache := newUIDCache(path)
	cache.Lookup(1000) // prime
	// Replace alice with carol at the same uid.
	if err := os.WriteFile(path, []byte("carol:x:1000:1000::/home/carol:/bin/bash\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cache.Refresh()
	if got := cache.Lookup(1000); got != "carol" {
		t.Fatalf("after Refresh, uid 1000 = %q, want carol", got)
	}
}
