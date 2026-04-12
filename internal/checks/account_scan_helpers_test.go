package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// --- ResolveWebRoots --------------------------------------------------

func TestResolveWebRootsWithAccountRoots(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "site1", "public")
	_ = os.MkdirAll(sub, 0700)

	cfg := &config.Config{AccountRoots: []string{filepath.Join(dir, "*/public")}}
	roots := ResolveWebRoots(cfg)
	if len(roots) != 1 || roots[0] != sub {
		t.Errorf("got %v, want [%s]", roots, sub)
	}
}

func TestResolveWebRootsNoAccountRootsNonCPanel(t *testing.T) {
	cfg := &config.Config{}
	roots := ResolveWebRoots(cfg)
	// Non-cPanel with no account_roots → nil
	if roots != nil {
		t.Errorf("expected nil, got %v", roots)
	}
}

func TestResolveWebRootsDeduplicates(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "site1")
	_ = os.MkdirAll(sub, 0700)

	cfg := &config.Config{AccountRoots: []string{
		filepath.Join(dir, "*"),
		filepath.Join(dir, "*"), // duplicate pattern
	}}
	roots := ResolveWebRoots(cfg)
	if len(roots) != 1 {
		t.Errorf("duplicates should be removed, got %v", roots)
	}
}

func TestResolveWebRootsNoMatch(t *testing.T) {
	cfg := &config.Config{AccountRoots: []string{"/nonexistent/*/public"}}
	roots := ResolveWebRoots(cfg)
	if len(roots) != 0 {
		t.Errorf("no match should return empty, got %v", roots)
	}
}

// --- LookupUID --------------------------------------------------------

func TestLookupUIDCurrentUser(t *testing.T) {
	// Current user should have a valid UID
	uid := LookupUID(os.Getenv("USER"))
	if uid < 0 {
		t.Skipf("current user lookup failed (USER=%q)", os.Getenv("USER"))
	}
}

func TestLookupUIDNonexistent(t *testing.T) {
	if uid := LookupUID("nonexistent_user_zzz"); uid != -1 {
		t.Errorf("nonexistent user should return -1, got %d", uid)
	}
}
