package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
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
		{"passthru,shell_exec,proc_open", false}, // real hardening
		{"pcntl_exec", false},                    // pcntl family
	}
	for _, c := range cases {
		if got := disableFunctionsNeutralized(c.val); got != c.want {
			t.Errorf("disableFunctionsNeutralized(%q) = %v, want %v", c.val, got, c.want)
		}
	}
}
