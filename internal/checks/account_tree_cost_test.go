package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// The reporter on issue 76 saw sustained CPU on a host serving many WordPress
// sites, with a real-time queue that was never overflowing. That leaves the
// periodic content checks as the suspect, and what they cost has never been
// measured against a tree of a known size. These benchmarks report cost per
// file so a host's account tree can be turned into an expected scan cost.
//
// Run with:
//
//	scripts/go-linux.sh go test ./internal/checks -run XXX -bench BenchmarkAccountTree -benchtime 1x

// buildAccountTree writes a tree shaped like a small WordPress install:
// PHP source, a few assets, and the nested directories a plugin set produces.
func buildAccountTree(tb testing.TB, root string, accounts, filesPerAccount int) {
	tb.Helper()
	php := []byte("<?php\n$opts = get_option('active_plugins');\nforeach ($opts as $p) { include_once WP_PLUGIN_DIR . '/' . $p; }\n")
	asset := []byte("body { margin: 0; padding: 0; font-family: system-ui, sans-serif; }\n")
	for account := 0; account < accounts; account++ {
		docroot := filepath.Join(root, fmt.Sprintf("account%02d", account), "public_html")
		for i := 0; i < filesPerAccount; i++ {
			dir := filepath.Join(docroot, "wp-content", "plugins", fmt.Sprintf("plugin%02d", i%20))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				tb.Fatal(err)
			}
			name := filepath.Join(dir, fmt.Sprintf("module%03d.php", i))
			if err := os.WriteFile(name, php, 0o644); err != nil {
				tb.Fatal(err)
			}
			if i%4 == 0 {
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("style%03d.css", i)), asset, 0o644); err != nil {
					tb.Fatal(err)
				}
			}
		}
	}
}

// useAccountTree points account discovery at the synthetic tree. The checks
// find accounts through the platform's home roots, not through the config, so
// a benchmark that only set account_roots measured an empty walk.
func useAccountTree(tb testing.TB, root string) *config.Config {
	tb.Helper()
	previous := accountHomeRoots
	tb.Cleanup(func() { accountHomeRoots = previous })
	accountHomeRoots = func() []string { return []string{root} }
	cfg := &config.Config{}
	cfg.AccountRoots = []string{root}
	return cfg
}

// The benchmarks below are meaningless if the checks never reach the tree, and
// an empty walk looks like a very fast scan. This is the guard that the
// harness measures real work.
func TestAccountTreeHarnessIsActuallyScanned(t *testing.T) {
	root, err := os.MkdirTemp("/run", "treecost-guard-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	buildAccountTree(t, root, 1, 4)
	docroot := filepath.Join(root, "account00", "public_html")
	if err := os.WriteFile(filepath.Join(docroot, "wso.php"), []byte("<?php eval($_POST[0]);"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := useAccountTree(t, root)

	findings := CheckWebshells(context.Background(), cfg, nil)

	for _, f := range findings {
		if strings.Contains(f.FilePath, "wso.php") || strings.Contains(f.Message, "wso.php") {
			return
		}
	}
	t.Fatalf("planted webshell was not reported; the harness is not scanning the tree (%d findings)", len(findings))
}

func benchmarkAccountTreeCheck(b *testing.B, name string, check CheckFunc, accounts, filesPerAccount int) {
	root, err := os.MkdirTemp("/run", "treecost-")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = os.RemoveAll(root) })
	buildAccountTree(b, root, accounts, filesPerAccount)
	cfg := useAccountTree(b, root)
	files := accounts * filesPerAccount

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		check(context.Background(), cfg, nil)
	}
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*files), "ns/file")
}

func BenchmarkAccountTreePHPContent(b *testing.B) {
	benchmarkAccountTreeCheck(b, "php_content", CheckPHPContent, 10, 200)
}

func BenchmarkAccountTreeWebshells(b *testing.B) {
	benchmarkAccountTreeCheck(b, "webshells", CheckWebshells, 10, 200)
}

func BenchmarkAccountTreeFilesystem(b *testing.B) {
	benchmarkAccountTreeCheck(b, "filesystem", CheckFilesystem, 10, 200)
}
