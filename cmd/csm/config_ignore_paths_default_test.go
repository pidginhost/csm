package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// Shipped configs must not exempt whole directory classes from scanning: an
// attacker who learns the list drops the webshell there.
func TestShippedConfigsScanCacheAndLibraryPaths(t *testing.T) {
	rendered := filepath.Join(t.TempDir(), "csm.yaml")
	if err := deployDefaultConfig(rendered); err != nil {
		t.Fatalf("deployDefaultConfig: %v", err)
	}
	sources := map[string]string{
		"installer template": rendered,
		"packaged default":   filepath.Join("..", "..", "build", "packaging", "csm.yaml.default"),
		"production example": filepath.Join("..", "..", "configs", "csm.yaml.production.example"),
	}
	paths := []string{
		"/home/user/public_html/wp-content/cache/shell.php",
		"/home/user/public_html/vendor/acme/lib/shell.php",
		"/home/user/public_html/wp-content/plugins/imunify-security/shell.php",
	}
	for name, path := range sources {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := config.LoadBytes(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, p := range paths {
			if checks.PathMatchesIgnore(p, cfg.Suppressions.IgnorePaths) {
				t.Errorf("%s skips %s via ignore_paths %v", name, p, cfg.Suppressions.IgnorePaths)
			}
		}
	}
	fromCode, err := config.LoadBytes([]byte("hostname: test\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if checks.PathMatchesIgnore(p, fromCode.Suppressions.IgnorePaths) {
			t.Errorf("code default skips %s", p)
		}
	}
}
