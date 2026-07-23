package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/state"
)

// phpIniFS builds a map-backed mock filesystem from full file paths, deriving
// the directory tree so a nested walk (ReadDir/Stat) resolves correctly.
func phpIniFS(files map[string]string) *mockOS {
	dirs := map[string]bool{}
	for p := range files {
		for d := filepath.Dir(p); d != "/" && d != "."; d = filepath.Dir(d) {
			dirs[d] = true
		}
	}
	info := func(name string, isDir bool) os.FileInfo {
		mode := os.FileMode(0644)
		if isDir {
			mode = os.ModeDir | 0755
		}
		return accountScanFakeInfo{name: filepath.Base(name), isDir: isDir, mode: mode}
	}
	return &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if _, ok := files[name]; ok {
				return info(name, false), nil
			}
			if dirs[name] {
				return info(name, true), nil
			}
			return nil, os.ErrNotExist
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			if !dirs[name] {
				return nil, os.ErrNotExist
			}
			seen := map[string]bool{}
			var out []os.DirEntry
			add := func(p string, isDir bool) {
				base := filepath.Base(p)
				if filepath.Dir(p) != name || seen[base] {
					return
				}
				seen[base] = true
				out = append(out, realDirEntry{name: base, info: info(p, isDir)})
			}
			for p := range files {
				add(p, false)
			}
			for d := range dirs {
				add(d, true)
			}
			return out, nil
		},
		readFile: func(name string) ([]byte, error) {
			if c, ok := files[name]; ok {
				return []byte(c), nil
			}
			return nil, os.ErrNotExist
		},
	}
}

func newPHPConfigStore(t *testing.T) *state.Store {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// A php.ini planted deep under the docroot with a neutralized
// disable_functions (the 0xNix/Seobarbar bypass, 2026-07-23) must be
// flagged on first sight -- the deep check previously only watched
// .user.ini at the docroot root and only alerted on later changes.
func TestCheckPHPConfigChangesFlagsPlantedNestedPhpIni(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "victim")
	withMockOS(t, phpIniFS(map[string]string{
		"/home/victim/public_html/wp-includes/assets/php.ini": "disable_functions=ByPassed By 0xNix(Seobarbar)\n",
	}))
	findings := CheckPHPConfigChanges(ctx, &config.Config{}, newPHPConfigStore(t))
	if got := countByCheck(findings, "php_config_change"); got != 1 {
		t.Fatalf("php_config_change on planted nested php.ini = %d, want 1: %+v", got, findings)
	}
}

func TestCheckPHPConfigChangesKeepsUnchangedDangerousConfigActive(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "victim")
	withMockOS(t, phpIniFS(map[string]string{
		"/home/victim/public_html/php.ini": "disable_functions = bypassed by 0xnix\n",
	}))
	st := newPHPConfigStore(t)

	for run := 1; run <= 2; run++ {
		findings := CheckPHPConfigChanges(ctx, &config.Config{}, st)
		if got := countByCheck(findings, "php_config_change"); got != 1 {
			t.Fatalf("run %d php_config_change = %d, want 1: %+v", run, got, findings)
		}
	}
}

func TestCheckPHPConfigChangesConcurrentScansKeepStateConsistent(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "victim")
	withMockOS(t, phpIniFS(map[string]string{
		"/home/victim/public_html/php.ini": "disable_functions = bypassed by 0xnix\n",
	}))
	st := newPHPConfigStore(t)

	const scans = 8
	results := make(chan []alert.Finding, scans)
	var wg sync.WaitGroup
	for i := 0; i < scans; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- CheckPHPConfigChanges(ctx, &config.Config{}, st)
		}()
	}
	wg.Wait()
	close(results)

	for findings := range results {
		if got := countByCheck(findings, "php_config_change"); got != 1 {
			t.Fatalf("concurrent php_config_change = %d, want 1: %+v", got, findings)
		}
	}
	raw, ok := st.GetRaw("_phpini:/home/victim/public_html/php.ini")
	decoded := decodePHPIniFileState(raw)
	if !ok || !decoded.Assessed || decoded.Hash == "" {
		t.Fatalf("concurrent state inconsistent: ok=%v raw=%q", ok, raw)
	}
}

func TestCheckPHPConfigChangesMigratesLegacyHashState(t *testing.T) {
	const path = "/home/victim/public_html/php.ini"
	const content = "disable_functions = bypassed by 0xnix\n"
	ctx := ContextWithAccountScope(context.Background(), "victim")
	withMockOS(t, phpIniFS(map[string]string{path: content}))
	st := newPHPConfigStore(t)
	st.SetRaw("_phpini:"+path, hashBytes([]byte(content)))

	findings := CheckPHPConfigChanges(ctx, &config.Config{}, st)
	if got := countByCheck(findings, "php_config_change"); got != 1 {
		t.Fatalf("legacy-state php_config_change = %d, want 1: %+v", got, findings)
	}
	raw, ok := st.GetRaw("_phpini:" + path)
	migrated := decodePHPIniFileState(raw)
	if !ok || !migrated.Assessed || migrated.Hash != hashBytes([]byte(content)) {
		t.Fatalf("legacy state was not migrated: ok=%v raw=%q", ok, raw)
	}
}

func TestCheckPHPConfigChangesScansBeyondLegacyDepth(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "victim")
	withMockOS(t, phpIniFS(map[string]string{
		"/home/victim/public_html/a/b/c/d/e/f/g/h/php.ini": "disable_functions = none\n",
	}))
	findings := CheckPHPConfigChanges(ctx, &config.Config{}, newPHPConfigStore(t))
	if got := countByCheck(findings, "php_config_change"); got != 1 {
		t.Fatalf("deep php_config_change = %d, want 1: %+v", got, findings)
	}
}

func TestCheckPHPConfigChangesUsesAuthoritativeAddonDocroots(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "victim")
	const configPath = "/home/victim/tmp/site/php.ini"
	withMockOS(t, phpIniFS(map[string]string{
		userdataDomainsPath: "addon.example: victim==root==addon==example.com==/home/victim/tmp/site==192.0.2.10:80==192.0.2.10:443\n",
		configPath:          "disable_functions = none\n",
	}))

	findings := CheckPHPConfigChanges(ctx, &config.Config{}, newPHPConfigStore(t))
	if got := countByCheck(findings, "php_config_change"); got != 1 {
		t.Fatalf("authoritative addon-root php_config_change = %d, want 1: %+v", got, findings)
	}
	if findings[0].FilePath != configPath {
		t.Fatalf("addon-root finding path = %q, want %q", findings[0].FilePath, configPath)
	}
}

func TestCheckPHPConfigChangesUsesDocrootOutsidePrimaryHomeMount(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "victim")
	const configPath = "/home2/victim/public_html/php.ini"
	withMockOS(t, phpIniFS(map[string]string{
		userdataDomainsPath: "example.com: victim==root==main==example.com==/home2/victim/public_html\n",
		configPath:          "disable_functions = none\n",
	}))

	findings := CheckPHPConfigChanges(ctx, &config.Config{}, newPHPConfigStore(t))
	if got := countByCheck(findings, "php_config_change"); got != 1 {
		t.Fatalf("alternate-home php_config_change = %d, want 1: %+v", got, findings)
	}
	if findings[0].FilePath != configPath {
		t.Fatalf("alternate-home finding path = %q, want %q", findings[0].FilePath, configPath)
	}
}

func TestPHPConfigRealtimeRootPatternsIncludeCPanelHomeMounts(t *testing.T) {
	panel := platform.PanelCPanel
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	platform.SetOverrides(platform.Overrides{Panel: &panel})
	withMockOS(t, phpIniFS(map[string]string{
		userdataDomainsPath: strings.Join([]string{
			"primary.example: victim==root==main==example.com==/home/victim/public_html==192.0.2.10:80==192.0.2.10:443",
			"alternate.example: victim==root==addon==example.com==/home2/victim/addon==192.0.2.10:80==192.0.2.10:443",
			"external.example: victim==root==addon==example.com==/srv/vhosts/external==192.0.2.10:80==192.0.2.10:443",
			"custom-home.example: victim==root==addon==example.com==/srv/victim/site==192.0.2.10:80==192.0.2.10:443",
		}, "\n"),
	}))

	got := PHPConfigRealtimeRootPatterns(&config.Config{})
	want := []string{"/home/*", "/home2/*", "/srv/vhosts/external", "/srv/victim/site"}
	if len(got) != len(want) {
		t.Fatalf("realtime PHP config roots = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("realtime PHP config roots = %v, want %v", got, want)
		}
	}
}

func TestPHPConfigRealtimeRootPatternsPreferExplicitConfig(t *testing.T) {
	cfg := &config.Config{AccountRoots: []string{"/var/www/vhosts/*/httpdocs"}}
	got := PHPConfigRealtimeRootPatterns(cfg)
	if len(got) != 1 || got[0] != cfg.AccountRoots[0] {
		t.Fatalf("realtime PHP config roots = %v, want %v", got, cfg.AccountRoots)
	}
}

func TestCheckPHPConfigChangesFallsBackToAccountSubdirectories(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "victim")
	const configPath = "/home/victim/domains/example.com/public_html/php.ini"
	withMockOS(t, phpIniFS(map[string]string{
		configPath: "disable_functions = none\n",
	}))

	findings := CheckPHPConfigChanges(ctx, &config.Config{}, newPHPConfigStore(t))
	if got := countByCheck(findings, "php_config_change"); got != 1 {
		t.Fatalf("fallback account-root php_config_change = %d, want 1: %+v", got, findings)
	}
	if findings[0].FilePath != configPath {
		t.Fatalf("fallback account-root finding path = %q, want %q", findings[0].FilePath, configPath)
	}
}

func TestParseUserdataDomainRootsRejectsInvalidAccount(t *testing.T) {
	vhosts, complete := parseUserdataDomainRootsChecked(
		"example.com: ../../root==root==main==example.com==/srv/example\n",
	)
	if complete || len(vhosts) != 0 {
		t.Fatalf("invalid account parsed as complete vhost: complete=%v vhosts=%+v", complete, vhosts)
	}
}

func TestCheckPHPConfigChangesDoesNotRequireVhostServingIP(t *testing.T) {
	ctx, incomplete := withIncompleteCheckCollector(
		ContextWithAccountScope(context.Background(), "victim"),
	)
	const configPath = "/home/victim/addon/php.ini"
	withMockOS(t, phpIniFS(map[string]string{
		userdataDomainsPath: "addon.example: victim==root==addon==example.com==/home/victim/addon\n",
		configPath:          "memory_limit = 256M\n",
	}))

	_ = CheckPHPConfigChanges(ctx, &config.Config{}, newPHPConfigStore(t))
	if incomplete.contains("php_config_changes") {
		t.Fatal("missing vhost serving IP must not make a local config scan incomplete")
	}
}

func TestCheckPHPConfigChangesDoesNotAttributeHostMapErrorsToAccount(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "victim")
	withMockOS(t, phpIniFS(map[string]string{
		userdataDomainsPath: strings.Join([]string{
			"malformed row",
			"example.com: victim==root==main==example.com==/home/victim/public_html",
		}, "\n"),
		"/home/victim/public_html/php.ini": "memory_limit = 256M\n",
	}))

	findings := CheckPHPConfigChanges(ctx, &config.Config{}, newPHPConfigStore(t))
	if got := countByCheck(findings, "php_config_scan_incomplete"); got != 0 {
		t.Fatalf("host map errors attributed to account scan = %d, want 0: %+v", got, findings)
	}
}

// A benign new php.ini (no security-weakening directive) must not alert on
// first sight -- new-file alerting fires only on the strong bypass signals.
func TestCheckPHPConfigChangesIgnoresBenignNewPhpIni(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "victim")
	withMockOS(t, phpIniFS(map[string]string{
		"/home/victim/public_html/php.ini": "memory_limit = 256M\nupload_max_filesize = 64M\n",
	}))
	findings := CheckPHPConfigChanges(ctx, &config.Config{}, newPHPConfigStore(t))
	if got := countByCheck(findings, "php_config_change"); got != 0 {
		t.Fatalf("benign new php.ini flagged = %d, want 0: %+v", got, findings)
	}
}

// A legitimate .user.ini that actually disables the dangerous functions must
// not be flagged as a bypass.
func TestCheckPHPConfigChangesIgnoresLegitUserIni(t *testing.T) {
	ctx := ContextWithAccountScope(context.Background(), "victim")
	withMockOS(t, phpIniFS(map[string]string{
		"/home/victim/public_html/.user.ini": "disable_functions = exec,system,passthru,shell_exec,proc_open,popen\n",
	}))
	findings := CheckPHPConfigChanges(ctx, &config.Config{}, newPHPConfigStore(t))
	if got := countByCheck(findings, "php_config_change"); got != 0 {
		t.Fatalf("legit .user.ini flagged = %d, want 0: %+v", got, findings)
	}
}

func TestCheckPHPConfigChangesMarksUnreadableWalkIncomplete(t *testing.T) {
	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/home":
				return []os.DirEntry{testDirEntry{name: "victim", isDir: true}}, nil
			case "/home/victim":
				return []os.DirEntry{testDirEntry{name: "public_html", isDir: true}}, nil
			case "/home/victim/public_html":
				return nil, os.ErrPermission
			default:
				return nil, os.ErrNotExist
			}
		},
	})

	findings := CheckPHPConfigChanges(ctx, &config.Config{}, newPHPConfigStore(t))
	if !incomplete.contains("php_config_changes") {
		t.Fatal("unreadable document root must mark php_config_changes incomplete")
	}
	if got := countByCheck(findings, "php_config_scan_incomplete"); got != 1 {
		t.Fatalf("unreadable walk coverage findings = %d, want 1: %+v", got, findings)
	}
}

func TestCheckPHPConfigChangesMarksVanishedCandidateIncomplete(t *testing.T) {
	ctx, incomplete := withIncompleteCheckCollector(context.Background())
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			switch name {
			case "/home":
				return []os.DirEntry{testDirEntry{name: "victim", isDir: true}}, nil
			case "/home/victim":
				return []os.DirEntry{testDirEntry{name: "public_html", isDir: true}}, nil
			case "/home/victim/public_html":
				return []os.DirEntry{testDirEntry{name: "php.ini"}}, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		stat: func(string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	})

	_ = CheckPHPConfigChanges(ctx, &config.Config{}, newPHPConfigStore(t))
	if !incomplete.contains("php_config_changes") {
		t.Fatal("candidate removed during the scan must preserve prior findings")
	}
}

func TestCheckPHPConfigChangesFlagsUnscannableConfigFiles(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    os.FileMode
		size    int64
		message string
	}{
		{
			name:    "FIFO",
			mode:    os.ModeNamedPipe | 0o600,
			message: "Special file used as PHP configuration",
		},
		{
			name:    "oversized",
			mode:    0o600,
			size:    PHPConfigMaxBytes + 1,
			message: "PHP configuration too large to inspect",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, incomplete := withIncompleteCheckCollector(context.Background())
			const path = "/home/victim/public_html/php.ini"
			withMockOS(t, &mockOS{
				readDir: func(name string) ([]os.DirEntry, error) {
					switch name {
					case "/home":
						return []os.DirEntry{testDirEntry{name: "victim", isDir: true}}, nil
					case "/home/victim":
						return []os.DirEntry{testDirEntry{name: "public_html", isDir: true}}, nil
					case "/home/victim/public_html":
						return []os.DirEntry{testDirEntry{name: "php.ini"}}, nil
					default:
						return nil, os.ErrNotExist
					}
				},
				stat: func(name string) (os.FileInfo, error) {
					if name == path {
						return accountScanFakeInfo{name: "php.ini", mode: tc.mode, size: tc.size}, nil
					}
					return nil, os.ErrNotExist
				},
			})

			findings := CheckPHPConfigChanges(ctx, &config.Config{}, newPHPConfigStore(t))
			if got := countByCheck(findings, "php_config_change"); got != 1 {
				t.Fatalf("unscannable php_config_change = %d, want 1: %+v", got, findings)
			}
			if !strings.Contains(findings[0].Message, tc.message) {
				t.Fatalf("unscannable message = %q, want %q", findings[0].Message, tc.message)
			}
			if !incomplete.contains("php_config_changes") {
				t.Fatal("unscannable PHP configuration must mark the scan incomplete")
			}
		})
	}
}

func TestCollectPHPIniFilesStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	readCalled := false
	withMockOS(t, &mockOS{
		readDir: func(string) ([]os.DirEntry, error) {
			readCalled = true
			return nil, nil
		},
	})

	files, complete := collectPHPIniFilesContext(ctx, "/home/victim/public_html", phpIniWalkMaxDepth)
	if complete {
		t.Fatal("canceled walk reported complete")
	}
	if len(files) != 0 {
		t.Fatalf("canceled walk returned files: %v", files)
	}
	if readCalled {
		t.Fatal("canceled walk read a directory")
	}
}

func TestCollectPHPIniFilesMarksVanishedSubdirectoryIncomplete(t *testing.T) {
	const root = "/home/victim/public_html"
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name == root {
				return []os.DirEntry{testDirEntry{name: "vanished", isDir: true}}, nil
			}
			return nil, os.ErrNotExist
		},
	})

	files, complete := collectPHPIniFilesContext(context.Background(), root, phpIniWalkMaxDepth)
	if complete {
		t.Fatal("subdirectory removed during the walk reported complete")
	}
	if len(files) != 0 {
		t.Fatalf("vanished subdirectory returned files: %v", files)
	}
}

func TestPHPIniFallbackRootsStopsAtEntryLimit(t *testing.T) {
	withMockOS(t, &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name != "/home/victim" {
				return nil, os.ErrNotExist
			}
			return []os.DirEntry{
				testDirEntry{name: "domains-a", isDir: true},
				testDirEntry{name: "domains-b", isDir: true},
				testDirEntry{name: "domains-c", isDir: true},
			}, nil
		},
	})

	roots, complete, err := phpIniFallbackRoots(context.Background(), "victim", 10, 2)
	if err != nil {
		t.Fatalf("phpIniFallbackRoots error: %v", err)
	}
	if complete {
		t.Fatal("entry-limited fallback enumeration reported complete")
	}
	if len(roots) != 2 {
		t.Fatalf("entry-limited fallback roots = %v, want first two", roots)
	}
}

func TestCollectPHPIniFilesStreamsLargeDirectories(t *testing.T) {
	withMockOS(t, realOS{})
	root := t.TempDir()
	for i := 0; i < phpIniReadDirBatch*2+1; i++ {
		name := filepath.Join(root, fmt.Sprintf("ordinary-%04d.txt", i))
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(root, "php.ini")
	if err := os.WriteFile(configPath, []byte("memory_limit=256M\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	files, complete := collectPHPIniFilesContext(context.Background(), root, 0)
	if !complete {
		t.Fatal("bounded production directory walk reported incomplete")
	}
	if len(files) != 1 || files[0] != configPath {
		t.Fatalf("collected files = %v, want %s", files, configPath)
	}
}

func TestReadPHPIniFileRejectsSpecialAndOversizedFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		size int64
		want error
	}{
		{name: "FIFO", mode: os.ModeNamedPipe | 0o600, want: errPHPIniNonRegular},
		{name: "oversized", mode: 0o600, size: PHPConfigMaxBytes + 1, want: errPHPIniTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			readCalled := false
			withMockOS(t, &mockOS{
				stat: func(name string) (os.FileInfo, error) {
					return accountScanFakeInfo{
						name: filepath.Base(name),
						mode: tc.mode,
						size: tc.size,
					}, nil
				},
				readFile: func(string) ([]byte, error) {
					readCalled = true
					return nil, nil
				},
			})
			_, err := readPHPIniFile("/home/victim/public_html/php.ini")
			if !errors.Is(err, tc.want) {
				t.Fatalf("readPHPIniFile error = %v, want %v", err, tc.want)
			}
			if readCalled {
				t.Fatal("rejected file reached ReadFile")
			}
		})
	}
}

func TestReadAndAssessPHPIniFilesDoesNotSerializeDifferentPaths(t *testing.T) {
	entered := make(chan string, 2)
	release := make(chan struct{})
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			return accountScanFakeInfo{name: filepath.Base(name), mode: 0o600, size: 16}, nil
		},
		readFile: func(name string) ([]byte, error) {
			entered <- name
			<-release
			return []byte("memory_limit=256M\n"), nil
		},
	})

	st := newPHPConfigStore(t)
	paths := []string{
		"/home/alice/public_html/php.ini",
		"/home/bob/public_html/php.ini",
	}
	var wg sync.WaitGroup
	for i, path := range paths {
		if i == 1 {
			select {
			case <-entered:
			case <-time.After(time.Second):
				close(release)
				wg.Wait()
				t.Fatal("first PHP configuration read did not start")
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = readAndAssessPHPIniFile(st, path)
		}()
	}

	select {
	case <-entered:
		close(release)
	case <-time.After(time.Second):
		close(release)
		wg.Wait()
		t.Fatal("different PHP configuration paths were serialized")
	}
	wg.Wait()
}

func TestPHPINISecurityBypassParsesEffectiveDirectives(t *testing.T) {
	safe := strings.Join([]string{
		"disable_functions_backup = none",
		"; allow_url_include = on",
		"allow_url_include = true",
		"allow_url_include = off",
		"open_basedirectory = /",
	}, "\n")
	if got := PHPConfigSecurityBypasses(safe); len(got) != 0 {
		t.Fatalf("unrelated, commented, or overridden directives flagged: %v", got)
	}

	dangerous := strings.Join([]string{
		"\ufeffallow_url_include = yes ; PHP truthy value",
		`open_basedir = "/srv/www":"/" ; quoted root entry removes restriction`,
	}, "\n")
	got := PHPConfigSecurityBypasses(dangerous)
	if len(got) != 2 ||
		!strings.Contains(got[0], "allow_url_include") ||
		!strings.Contains(got[1], "open_basedir") {
		t.Fatalf("dangerous directives = %v, want allow_url_include then open_basedir", got)
	}

	sectioned := strings.Join([]string{
		"[PATH=/home/victim/public_html/evil]",
		"disable_functions = none",
		"[PHP]",
		"disable_functions = exec,system",
	}, "\n")
	got = PHPConfigSecurityBypasses(sectioned)
	if len(got) != 1 || !strings.Contains(got[0], "disable_functions") {
		t.Fatalf("dangerous path section was hidden by later section: %v", got)
	}

	overriddenSection := strings.Join([]string{
		"[PATH=/home/victim/public_html/evil]",
		"allow_url_include = on",
		"[PATH=/home/victim/public_html/evil]",
		"allow_url_include = off",
	}, "\n")
	if got := PHPConfigSecurityBypasses(overriddenSection); len(got) != 0 {
		t.Fatalf("same-section override flagged: %v", got)
	}

	ordinarySections := strings.Join([]string{
		"[PHP]",
		"allow_url_include = on",
		"[Date]",
		"allow_url_include = off",
	}, "\n")
	if got := PHPConfigSecurityBypasses(ordinarySections); len(got) != 0 {
		t.Fatalf("ordinary section headings changed global override semantics: %v", got)
	}
}

func TestDisableFunctionsNeutralized(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"", true},                               // cleared
		{"none", true},                           // explicit none
		{"bypassed by 0xnix(seobarbar)", true},   // junk camouflage (2026-07-23)
		{"show_source,phpinfo", true},            // disables nothing dangerous
		{"exec,system", false},                   // real hardening
		{"exec system", false},                   // PHP also accepts space separators
		{"exec\tsystem", true},                   // tabs remain part of one invalid name
		{"passthru,shell_exec,proc_open", false}, // real hardening
		{"pcntl_exec", false},                    // pcntl family
		{"SYSTEMD,notexec,pcntl", true},          // substrings disable nothing
		{"eval,assert", true},                    // language constructs cannot be disabled
		{`ex"ec",sys"tem"`, false},               // PHP concatenates quoted fragments
		{`"exec","system"`, false},               // each list item may be quoted
		{`"exec`, true},                          // malformed value disables nothing
		{`"ex\"ec",systemd`, true},               // escaped quote remains part of the name
		{`"systemd;exec"`, true},                 // semicolon inside quotes is not a comment
		{`"EXEC, system" ; generated`, false},    // quoted, case-insensitive list
	}
	for _, c := range cases {
		if got := DisableFunctionsNeutralized(c.val); got != c.want {
			t.Errorf("DisableFunctionsNeutralized(%q) = %v, want %v", c.val, got, c.want)
		}
	}
}

func TestPHPIniBoolEnabled(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"on", true},
		{"yes", true},
		{"2", true},
		{"-1", true},
		{"1.0", true},
		{"1foo", true},
		{"1e-2", true},
		{"0|1", true},
		{"1&0", false},
		{`"0|1"`, false},
		{`"1&0"`, true},
		{`"0"|"1"`, true},
		{"2^3", true},
		{"!0", true},
		{"~0", true},
		{"(1&0)|2", true},
		{"1|2&0", false},
		{"1|2^3", false},
		{"18446744073709551616", true},
		{strings.Repeat("!", phpIniExpressionMaxDepth+1) + "0", true},
		{"off", false},
		{"none", false},
		{"0", false},
		{"-0", false},
		{"0.5", false},
		{".5", false},
		{"0x1", false},
		{"enabled", false},
		{"NaN", false},
	} {
		if got := phpIniBoolEnabled(tc.value); got != tc.want {
			t.Errorf("phpIniBoolEnabled(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}
