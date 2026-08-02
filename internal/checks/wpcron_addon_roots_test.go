package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

type wpCronReadDirCounter struct {
	OS
	calls map[string]int
}

type wpCronFakeFileInfo struct {
	name string
	mode os.FileMode
}

func (f wpCronFakeFileInfo) Name() string       { return f.name }
func (f wpCronFakeFileInfo) Size() int64        { return 100 }
func (f wpCronFakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f wpCronFakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f wpCronFakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f wpCronFakeFileInfo) Sys() any           { return nil }

func (c *wpCronReadDirCounter) ReadDir(name string) ([]os.DirEntry, error) {
	c.calls[filepath.Clean(name)]++
	return c.OS.ReadDir(name)
}

func wpCronMockInstallInfo(name string) (os.FileInfo, error) {
	mode := os.FileMode(0o644)
	switch filepath.Base(name) {
	case "wp-admin", "wp-includes":
		mode = os.ModeDir | 0o755
	}
	return wpCronFakeFileInfo{name: filepath.Base(name), mode: mode}, nil
}

const wpCronScanConfig = `<?php
$table_prefix = 'wp_';
require_once ABSPATH . 'wp-settings.php';
`

func writeWPCronScanInstall(t *testing.T, dir, configBody string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"wp-config.php":   configBody,
		"wp-settings.php": "<?php // WordPress bootstrap\n",
		"wp-cron.php":     "<?php // WordPress cron endpoint\n",
		"wp-load.php":     "<?php // WordPress loader\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"wp-admin", "wp-includes"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "wp-config.php")
}

func scanWPCronForTest(dir, account string, depth int, findings *[]alert.Finding) {
	candidates := make(map[string]wpCronCandidate)
	_ = scanWPCronCandidates(context.Background(), dir, dir, account, depth, nil, candidates)
	for _, candidate := range sortedWPCronCandidates(candidates) {
		*findings = append(*findings, newWPCronFinding(candidate))
	}
}

// The detector only ever looked at /home/*/public_html, so a WordPress install
// serving an addon domain from /home/<user>/<domain>/ was invisible to it. On a
// live host that was 177 of 277 installs -- every one of them still running
// WP-Cron on page loads with no way for the fix to reach them.
func TestWPCronScanCoversAddonDomainDocroots(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")

	// main docroot plus an addon-domain docroot alongside it
	main := filepath.Join(home, "alice", "public_html")
	addon := filepath.Join(home, "alice", "shop.example.com")
	nested := filepath.Join(home, "bob", "blog.example.net", "wp")
	if err := os.MkdirAll(filepath.Join(home, "bob", "public_html"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{main, addon, nested} {
		writeWPCronScanInstall(t, d, wpCronScanConfig)
	}

	// authoritative cPanel map naming all three docroots
	mapData := strings.Join([]string{
		"example.com: alice==root==main==example.com==" + main + "==192.0.2.10:80==192.0.2.10:443====0==ea-php82",
		"shop.example.com: alice==root==addon==example.com==" + addon + "==192.0.2.10:80==192.0.2.10:443====0==ea-php74",
		"blog.example.net: bob==root==addon==example.net==" + filepath.Dir(nested) + "==192.0.2.11:80==192.0.2.11:443====0==ea-php83",
	}, "\n")

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == userdataDomainsPath {
				return []byte(mapData), nil
			}
			return os.ReadFile(name)
		},
		readDir: os.ReadDir,
		stat:    os.Stat,
		lstat:   os.Lstat,
		glob:    filepath.Glob,
	})

	cfg := &config.Config{}
	enabled := true
	cfg.Performance.Enabled = &enabled
	cfg.AccountRoots = []string{filepath.Join(home, "*", "public_html")}

	findings := CheckWPCron(context.Background(), cfg, nil)

	// The finding-to-remediation contract carries the path in Details, never
	// FilePath. AutoFixWPCron and the Web UI both parse this exact field.
	found := make(map[string]int)
	for _, f := range findings {
		if f.FilePath != "" {
			t.Errorf("perf_wp_cron FilePath = %q, want empty", f.FilePath)
		}
		path := extractWPConfigPath(f.Details)
		if path == "" {
			t.Errorf("finding Details has no wp-config path: %q", f.Details)
			continue
		}
		found[path]++
	}
	for _, want := range []string{
		filepath.Join(main, "wp-config.php"),
		filepath.Join(addon, "wp-config.php"),
		filepath.Join(nested, "wp-config.php"),
	} {
		if found[want] != 1 {
			t.Errorf("perf_wp_cron findings for %s = %d, want 1", want, found[want])
		}
	}
}

// Nested vhost roots must not duplicate a finding already owned by the more
// specific root, but dropping the nested root loses sites below the broader
// root's depth limit. The deeper site is three levels below parent and only
// two below nested.
func TestWPCronNestedRootsAreScannedOnceWithoutLosingDepth(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "home", "alice", "public_html")
	nested := filepath.Join(parent, "addon")
	direct := writeWPCronScanInstall(t, nested, wpCronScanConfig)
	deep := writeWPCronScanInstall(t, filepath.Join(nested, "deep", "site"), wpCronScanConfig)
	counter := &wpCronReadDirCounter{OS: realOS{}, calls: make(map[string]int)}
	withMockOS(t, counter)

	cfg := &config.Config{AccountRoots: []string{parent, nested}}
	findings := CheckWPCron(context.Background(), cfg, nil)

	counts := make(map[string]int)
	for _, f := range findings {
		counts[extractWPConfigPath(f.Details)]++
	}
	for _, path := range []string{direct, deep} {
		if counts[path] != 1 {
			t.Errorf("findings for %s = %d, want 1; all=%+v", path, counts[path], findings)
		}
	}
	if counter.calls[nested] != 1 {
		t.Errorf("nested vhost was walked %d times, want once", counter.calls[nested])
	}
}

// A cPanel map is privileged scan input. A malformed owner/path pairing or a
// symlinked root must not turn the shallow WordPress check into a walk outside
// that account's home.
func TestWPCronScanRejectsUnsafeCPanelDocroots(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	main := filepath.Join(home, "alice", "public_html")
	safe := filepath.Join(home, "alice", "safe.example")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(main, 0o755); err != nil {
		t.Fatal(err)
	}
	safeConfig := writeWPCronScanInstall(t, safe, wpCronScanConfig)
	writeWPCronScanInstall(t, outside, wpCronScanConfig)
	linked := filepath.Join(home, "alice", "linked.example")
	if err := os.Symlink(outside, linked); err != nil {
		t.Fatal(err)
	}

	mapData := strings.Join([]string{
		"safe.example: alice==root==addon==example.com==" + safe + "==192.0.2.10:80",
		"etc.example: alice==root==addon==example.com==/etc==192.0.2.10:80",
		"other.example: alice==root==addon==example.com==" + filepath.Join(home, "bob", "site") + "==192.0.2.10:80",
		"broad.example: alice==root==addon==example.com==" + filepath.Join(home, "alice") + "==192.0.2.10:80",
		"linked.example: alice==root==addon==example.com==" + linked + "==192.0.2.10:80",
	}, "\n")
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == userdataDomainsPath {
				return []byte(mapData), nil
			}
			return os.ReadFile(name)
		},
		readDir: os.ReadDir,
		stat:    os.Stat,
		lstat:   os.Lstat,
		glob:    filepath.Glob,
	})

	cfg := &config.Config{AccountRoots: []string{main}}
	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	findings := CheckWPCron(ctx, cfg, nil)
	if len(findings) != 1 || extractWPConfigPath(findings[0].Details) != safeConfig {
		t.Fatalf("unsafe map roots affected findings: %+v", findings)
	}
	if !incomplete.contains("perf_wp_cron") {
		t.Fatal("unsafe cPanel rows must mark the scan incomplete")
	}
}

// A wp-config.php filename alone is not proof of a WordPress install. The
// auto-response edits that file and installs cron, so orphaned copies and
// unrelated files must not become destructive false positives.
func TestWPCronScanRequiresWordPressCoreFiles(t *testing.T) {
	root := t.TempDir()
	fake := filepath.Join(root, "not-wordpress")
	if err := os.MkdirAll(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fake, "wp-config.php"), []byte(wpCronScanConfig), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{AccountRoots: []string{root}}
	if findings := CheckWPCron(context.Background(), cfg, nil); len(findings) != 0 {
		t.Fatalf("orphaned wp-config.php produced destructive finding: %+v", findings)
	}
}

func TestWPCronScanRequiresActiveWordPressBootstrap(t *testing.T) {
	cases := map[string]string{
		"quoted table prefix": `<?php
$example = "$table_prefix = 'wp_'";
require_once ABSPATH . 'wp-settings.php';
`,
		"quoted bootstrap": `<?php
$table_prefix = 'wp_';
$bootstrap = "require_once ABSPATH . 'wp-settings.php';";
`,
		"bootstrap variable": `<?php
$table_prefix = 'wp_';
$require_once = 'wp-settings.php';
`,
	}
	for name, configBody := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			configPath := writeWPCronScanInstall(t, root, configBody)
			cfg := &config.Config{AccountRoots: []string{root}}
			if findings := CheckWPCron(context.Background(), cfg, nil); len(findings) != 0 {
				t.Fatalf("inactive WordPress sample produced destructive finding for %s: %+v", configPath, findings)
			}
		})
	}
}

// The finding limit must rotate deterministically through the sorted config
// paths. Otherwise every hourly run returns the same first 30 sites and addon
// domains later in the map can never reach auto-response.
func TestWPCronFindingCapMakesNonStarvingProgress(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sites")
	all := make(map[string]struct{})
	var roots []string
	for i := 0; i < 61; i++ {
		siteRoot := filepath.Join(root, fmt.Sprintf("site-%03d", i))
		path := writeWPCronScanInstall(t, siteRoot, wpCronScanConfig)
		roots = append(roots, siteRoot)
		all[path] = struct{}{}
	}
	store, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	cfg := &config.Config{AccountRoots: roots}
	seen := make(map[string]struct{})
	wantCounts := []int{30, 30, 30}
	for run, wantCount := range wantCounts {
		findings := CheckWPCron(context.Background(), cfg, store)
		if len(findings) != wantCount {
			t.Fatalf("run %d findings = %d, want %d", run+1, len(findings), wantCount)
		}
		paths := make([]string, 0, len(findings))
		for _, f := range findings {
			path := extractWPConfigPath(f.Details)
			paths = append(paths, path)
			seen[path] = struct{}{}
		}
		if !sort.StringsAreSorted(paths) {
			t.Fatalf("run %d paths are not deterministic: %v", run+1, paths)
		}
	}
	if len(seen) != len(all) {
		t.Fatalf("three capped runs covered %d/%d sites", len(seen), len(all))
	}
}

func TestWPCronFindingCapResumesWithinRootAfterRestart(t *testing.T) {
	base := t.TempDir()
	firstRoot := filepath.Join(base, "a-root")
	laterRoot := filepath.Join(base, "z-root")
	remaining := make(map[string]struct{})
	for i := 0; i < 35; i++ {
		path := writeWPCronScanInstall(t, filepath.Join(firstRoot, fmt.Sprintf("site-%02d", i)), wpCronScanConfig)
		if i >= wpCronFindingLimit {
			remaining[path] = struct{}{}
		}
	}
	laterPath := writeWPCronScanInstall(t, laterRoot, wpCronScanConfig)
	remaining[laterPath] = struct{}{}

	stateDir := filepath.Join(t.TempDir(), "state")
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AccountRoots: []string{firstRoot, laterRoot}}
	if findings := CheckWPCron(context.Background(), cfg, store); len(findings) != wpCronFindingLimit {
		t.Fatalf("first run findings = %d, want %d", len(findings), wpCronFindingLimit)
	}
	if closeErr := store.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	store, err = state.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	findings := CheckWPCron(context.Background(), cfg, store)
	if len(findings) != len(remaining) {
		t.Fatalf("resumed findings = %d, want %d: %+v", len(findings), len(remaining), findings)
	}
	for _, finding := range findings {
		path := extractWPConfigPath(finding.Details)
		if _, ok := remaining[path]; !ok {
			t.Errorf("resumed scan repeated or skipped past cursor: %s", path)
		}
		delete(remaining, path)
	}
	if len(remaining) != 0 {
		t.Fatalf("resumed scan starved paths: %v", remaining)
	}
}

// A docroot named in the map but owned by nobody, or missing, must not panic or
// produce a finding.
func TestWPCronScanToleratesMissingDocroots(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	main := filepath.Join(home, "alice", "public_html")
	if err := os.MkdirAll(main, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(home, "alice", "gone.example.com")
	mapData := "gone.example.com: alice==root==addon==example.com==" + missing + "==192.0.2.10:80==192.0.2.10:443====0==ea-php82"
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == userdataDomainsPath {
				return []byte(mapData), nil
			}
			return os.ReadFile(name)
		},
		readDir: os.ReadDir,
		stat:    os.Stat,
		lstat:   os.Lstat,
		glob:    filepath.Glob,
	})
	cfg := &config.Config{AccountRoots: []string{main}}
	enabled := true
	cfg.Performance.Enabled = &enabled
	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	if f := CheckWPCron(ctx, cfg, nil); len(f) != 0 {
		t.Errorf("expected no findings for a missing docroot, got %d", len(f))
	}
	if incomplete.contains("perf_wp_cron") {
		t.Fatal("a stale but safely scoped missing docroot must not make the scan incomplete")
	}
}
