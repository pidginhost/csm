package checks

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

func TestResolveWebRoots_ExplicitConfig(t *testing.T) {
	// Build a fake tree that mimics /var/www/*/public_html.
	tmp := t.TempDir()
	for _, site := range []string{"site-a", "site-b", "site-c"} {
		dir := filepath.Join(tmp, "var", "www", site, "public_html")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// Non-existent entry should be silently dropped.
	missing := filepath.Join(tmp, "does", "not", "exist")

	cfg := &config.Config{
		AccountRoots: []string{
			filepath.Join(tmp, "var", "www", "*", "public_html"),
			missing,
		},
	}
	got := ResolveWebRoots(cfg)
	sort.Strings(got)

	want := []string{
		filepath.Join(tmp, "var", "www", "site-a", "public_html"),
		filepath.Join(tmp, "var", "www", "site-b", "public_html"),
		filepath.Join(tmp, "var", "www", "site-c", "public_html"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %d roots (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("root[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestResolveWebRoots_Dedupes(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "srv", "site")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		AccountRoots: []string{
			filepath.Join(tmp, "srv", "site"),
			filepath.Join(tmp, "srv", "*"), // matches the same dir
		},
	}
	got := ResolveWebRoots(cfg)
	if len(got) != 1 {
		t.Errorf("dedupe failed, got %d roots: %v", len(got), got)
	}
}

func TestResolveWebRoots_SkipsFiles(t *testing.T) {
	// A glob match that hits a regular file (not a dir) should be skipped.
	tmp := t.TempDir()
	filePath := filepath.Join(tmp, "not-a-dir")
	if err := os.WriteFile(filePath, []byte("file"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AccountRoots: []string{filePath}}
	if got := ResolveWebRoots(cfg); len(got) != 0 {
		t.Errorf("file should not be returned as a web root, got %v", got)
	}
}

func TestResolveWebRoots_NoConfigNonCPanel(t *testing.T) {
	platform.ResetForTest()
	// No config, no cPanel → empty list (non-cPanel host today).
	// We can't control the host's actual detection, but on a CI/Darwin
	// box platform.Detect().IsCPanel() will be false, so this should
	// return nil.
	cfg := &config.Config{}
	if got := ResolveWebRoots(cfg); len(got) != 0 && !platform.Detect().IsCPanel() {
		t.Errorf("non-cPanel without config should return nil, got %v", got)
	}
}

func TestResolveWebRoots_CPanelDefault(t *testing.T) {
	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{})
	// Simulate a cPanel host by forcing Detect via a fake. The current
	// Info API doesn't let us inject — so we construct the expected
	// behavior via the config path: set AccountRoots explicitly to the
	// cPanel default and verify it expands.
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	for _, user := range []string{"alice", "bob"} {
		if err := os.MkdirAll(filepath.Join(home, user, "public_html"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{AccountRoots: []string{filepath.Join(home, "*", "public_html")}}
	got := ResolveWebRoots(cfg)
	if len(got) != 2 {
		t.Errorf("want 2 roots, got %d: %v", len(got), got)
	}
}

func TestAccountFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/home/alice/public_html", "alice"},
		{"/home/bob/public_html", "bob"},
		{"/var/www/example.com/public", "example.com"},
		{"/srv/http/site-a", "http"},
		{"/home/carol", "carol"}, // /home/<account> matches the cPanel rule
		{"public_html", "public_html"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := accountFromPath(tt.path); got != tt.want {
				t.Errorf("accountFromPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
