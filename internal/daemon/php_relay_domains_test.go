package daemon

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func withLocalDomainFiles(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	old := localDomainPaths
	localDomainPaths = []string{filepath.Join(dir, "localdomains"), filepath.Join(dir, "virtualdomains")}
	t.Cleanup(func() { localDomainPaths = old })
	return localDomainPaths
}

func writeLocalDomains(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadLocalDomainsRequiresCompleteInventory(t *testing.T) {
	for _, failedIndex := range []int{0, 1} {
		t.Run(filepath.Base([]string{"localdomains", "virtualdomains"}[failedIndex]), func(t *testing.T) {
			paths := withLocalDomainFiles(t)
			writeLocalDomains(t, paths[1-failedIndex], "example.com\n")
			// A directory produces a read error even when tests run as root.
			if err := os.Mkdir(paths[failedIndex], 0o700); err != nil {
				t.Fatal(err)
			}
			if _, known := readLocalDomains(); known {
				t.Fatal("partially unreadable inventory was reported as complete")
			}
			cache := &localDomainCache{ttl: time.Minute}
			old := phpRelayIsLocalDomain
			phpRelayIsLocalDomain = cache.has
			t.Cleanup(func() { phpRelayIsLocalDomain = old })
			if sendsOffHost([]string{"office@example.net"}) {
				t.Fatal("a domain missing from the partial inventory counted as outbound")
			}
		})
	}
}

func TestReadLocalDomainsMergesAvailableFiles(t *testing.T) {
	paths := withLocalDomainFiles(t)
	if _, known := readLocalDomains(); known {
		t.Fatal("absent files reported as known")
	}
	writeLocalDomains(t, paths[0], " # comment\n Example.COM \n\n")
	if domains, known := readLocalDomains(); !known || !reflect.DeepEqual(domains, map[string]bool{"example.com": true}) {
		t.Fatalf("single available file = %v, %v", domains, known)
	}
	writeLocalDomains(t, paths[1], "Example.NET: exampleuser\n")
	if domains, known := readLocalDomains(); !known || !reflect.DeepEqual(domains, map[string]bool{"example.com": true, "example.net": true}) {
		t.Fatalf("merged files = %v, %v", domains, known)
	}
}

func TestLocalDomainCacheRefreshesSuccessAndFailure(t *testing.T) {
	paths := withLocalDomainFiles(t)
	cache := &localDomainCache{ttl: time.Minute}
	if _, known := cache.has("example.com"); known {
		t.Fatal("absent inventory reported as known")
	}
	writeLocalDomains(t, paths[0], "example.com\n")
	if _, known := cache.has("example.com"); known {
		t.Fatal("failed read was not cached")
	}
	cache.loadedAt = time.Now().Add(-2 * cache.ttl)
	if local, known := cache.has("EXAMPLE.COM"); !local || !known {
		t.Fatalf("recovered inventory = %v, %v", local, known)
	}
	writeLocalDomains(t, paths[0], "example.net\n")
	if local, known := cache.has("example.com"); !local || !known {
		t.Fatalf("successful read was not cached: %v, %v", local, known)
	}
	cache.loadedAt = time.Now().Add(-2 * cache.ttl)
	if local, known := cache.has("example.com"); local || !known {
		t.Fatalf("removed domain still local: %v, %v", local, known)
	}
	if local, known := cache.has("example.net"); !local || !known {
		t.Fatalf("new domain missing: %v, %v", local, known)
	}
	if err := os.Mkdir(paths[1], 0o700); err != nil {
		t.Fatal(err)
	}
	cache.loadedAt = time.Now().Add(-2 * cache.ttl)
	if _, known := cache.has("example.net"); known {
		t.Fatal("failed refresh left the inventory known")
	}
}
