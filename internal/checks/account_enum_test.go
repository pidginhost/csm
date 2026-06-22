package checks

import (
	"errors"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// mockDirEntryByName is a minimal os.DirEntry whose only meaningful field is
// Name. Used exclusively for the registry and home directory mocks below.
type mockDirEntryByName struct {
	name  string
	isDir bool
}

func (e mockDirEntryByName) Name() string               { return e.name }
func (e mockDirEntryByName) IsDir() bool                { return e.isDir }
func (e mockDirEntryByName) Type() os.FileMode          { return 0 }
func (e mockDirEntryByName) Info() (os.FileInfo, error) { return nil, nil }

func dirEntry(name string, isDir bool) os.DirEntry {
	return mockDirEntryByName{name: name, isDir: isDir}
}

// TestEnumerateScanAccounts_RegistryWithHomes covers the primary case: registry
// contains {alice, bob, sys} but only alice and bob have /home/<user> dirs.
// sys must be excluded. Result must be sorted.
func TestEnumerateScanAccounts_RegistryWithHomes(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/var/cpanel/users":
				return []os.DirEntry{
					dirEntry("alice", false),
					dirEntry("bob", false),
					dirEntry("sys", false),
				}, nil
			case "/home":
				return []os.DirEntry{
					dirEntry("alice", true),
					dirEntry("bob", true),
					// sys is absent from /home
				}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	got, err := EnumerateScanAccounts(&config.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"alice", "bob"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestEnumerateScanAccounts_SortedDeduplicated verifies that even if the FS
// returns names out of order the result is sorted and de-duplicated.
func TestEnumerateScanAccounts_SortedDeduplicated(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/var/cpanel/users":
				// Intentionally out of order; charlie appears twice (shouldn't
				// be possible with real FS but the code must handle it).
				return []os.DirEntry{
					dirEntry("charlie", false),
					dirEntry("alice", false),
					dirEntry("bob", false),
					dirEntry("charlie", false),
				}, nil
			case "/home":
				return []os.DirEntry{
					dirEntry("alice", true),
					dirEntry("bob", true),
					dirEntry("charlie", true),
				}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	got, err := EnumerateScanAccounts(&config.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"alice", "bob", "charlie"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestEnumerateScanAccounts_MissingRegistry verifies the fallback when
// /var/cpanel/users is absent (non-cPanel platform): the function falls back to
// enumerating /home subdirectories that pass name validation.
func TestEnumerateScanAccounts_MissingRegistry(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/var/cpanel/users":
				return nil, os.ErrNotExist
			case "/home":
				return []os.DirEntry{
					dirEntry("alice", true),
					dirEntry("bob", true),
				}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	got, err := EnumerateScanAccounts(&config.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fallback: /home entries alice and bob must be returned sorted.
	want := []string{"alice", "bob"}
	if len(got) != len(want) {
		t.Fatalf("fallback: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestEnumerateScanAccounts_TraversalJunkExcluded checks that entries whose
// names contain path separators or are dot-only are excluded regardless of
// which code path is taken (registry or home-dir fallback).
func TestEnumerateScanAccounts_TraversalJunkExcluded(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/var/cpanel/users":
				return []os.DirEntry{
					dirEntry("alice", false),
					dirEntry("..", false),  // dot-dot
					dirEntry("a/b", false), // slash in name
					dirEntry(".", false),   // dot
					dirEntry("", false),    // empty
				}, nil
			case "/home":
				return []os.DirEntry{
					dirEntry("alice", true),
				}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	got, err := EnumerateScanAccounts(&config.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "alice" {
		t.Errorf("got %v, want [alice]", got)
	}
}

// TestEnumerateScanAccounts_RegistryReadError verifies that a hard FS error
// reading /var/cpanel/users (not just ErrNotExist) is propagated as an error.
func TestEnumerateScanAccounts_RegistryReadError(t *testing.T) {
	hardErr := errors.New("disk I/O error")
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == "/var/cpanel/users" {
				return nil, hardErr
			}
			return nil, os.ErrNotExist
		},
	})

	got, err := EnumerateScanAccounts(&config.Config{})
	if err == nil {
		t.Fatalf("expected error, got %v", got)
	}
}

// TestEnumerateScanAccounts_FallbackHomeReadError verifies that in the
// registry-absent fallback path, a hard /home read error (not ErrNotExist) is
// propagated -- /home is the sole source of truth there, so a broken read must
// not masquerade as an empty host.
func TestEnumerateScanAccounts_FallbackHomeReadError(t *testing.T) {
	hardErr := errors.New("permission denied")
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/var/cpanel/users":
				return nil, os.ErrNotExist // trigger fallback
			case "/home":
				return nil, hardErr
			}
			return nil, os.ErrNotExist
		},
	})

	got, err := EnumerateScanAccounts(&config.Config{})
	if err == nil {
		t.Fatalf("expected error from fallback /home read, got %v", got)
	}
}

// TestEnumerateScanAccounts_EmptyRegistry returns an empty (non-nil) slice
// when /var/cpanel/users exists but is empty (no accounts at all).
func TestEnumerateScanAccounts_EmptyRegistry(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/var/cpanel/users":
				return []os.DirEntry{}, nil
			case "/home":
				return []os.DirEntry{}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	got, err := EnumerateScanAccounts(&config.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
}
