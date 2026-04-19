package checks

import (
	"context"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pidginhost/csm/internal/store"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		installed string
		available string
		wantMajor bool
		wantMinor int
	}{
		{"3.32.5", "4.0.1", true, 0},
		{"6.1.3", "6.4.2", false, 3},
		{"6.1.3", "6.1.5", false, 0},
		{"5.6", "5.6", false, 0},
		{"1.9.9", "1.9.9", false, 0},
		{"6.4.0", "6.5.13", false, 1},
		{"6.4.0", "6.7.0", false, 3},
		{"", "4.0.1", false, 0},
		{"3.0", "", false, 0},
	}
	for _, tt := range tests {
		gotMajor, gotMinor := compareVersions(tt.installed, tt.available)
		if gotMajor != tt.wantMajor || gotMinor != tt.wantMinor {
			t.Errorf("compareVersions(%q, %q) = (%v, %d), want (%v, %d)",
				tt.installed, tt.available, gotMajor, gotMinor, tt.wantMajor, tt.wantMinor)
		}
	}
}

func TestPluginAlertSeverity(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		available string
		wantSev   string
	}{
		{"major gap", "3.32.5", "4.0.1", "critical"},
		{"3 minor", "6.1.3", "6.4.2", "high"},
		{"1 minor", "6.4.0", "6.5.13", "warning"},
		{"same version", "5.6", "5.6", ""},
		{"patch only", "6.1.3", "6.1.5", "warning"},
		{"installed ahead", "6.5.0", "6.4.9", ""},
		{"installed ahead major", "5.0.0", "4.9.9", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pluginAlertSeverity(tt.installed, tt.available)
			if got != tt.wantSev {
				t.Errorf("pluginAlertSeverity(%q, %q) = %q, want %q",
					tt.installed, tt.available, got, tt.wantSev)
			}
		})
	}
}

func TestParseWPOrgResponse(t *testing.T) {
	body := `{"name":"Elementor","slug":"elementor","version":"4.0.1","tested":"6.9.4"}`
	info, err := parseWPOrgPluginResponse([]byte(body))
	if err != nil {
		t.Fatalf("parseWPOrgPluginResponse: %v", err)
	}
	if info.LatestVersion != "4.0.1" {
		t.Errorf("LatestVersion = %q, want %q", info.LatestVersion, "4.0.1")
	}
	if info.TestedUpTo != "6.9.4" {
		t.Errorf("TestedUpTo = %q, want %q", info.TestedUpTo, "6.9.4")
	}
}

func TestParseWPOrgResponseNotFound(t *testing.T) {
	body := `{"error":"Plugin not found."}`
	_, err := parseWPOrgPluginResponse([]byte(body))
	if err == nil {
		t.Error("expected error for plugin not found")
	}
}

func TestFailureBreakdown(t *testing.T) {
	if got := failureBreakdown(0, 0, 0); got != "" {
		t.Errorf("no failures should produce empty suffix, got %q", got)
	}
	got := failureBreakdown(3, 1, 2)
	want := " (timeout=3 exec_fail=1 json_fail=2)"
	if got != want {
		t.Errorf("failureBreakdown(3,1,2) = %q, want %q", got, want)
	}
}

// captureStderr redirects os.Stderr while fn runs and returns what fn wrote.
// Used to assert that refreshPluginCache emits exactly one aggregated summary
// line instead of one per broken site.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stderr = orig
	return <-done
}

// setupPluginStore opens a bbolt store, installs it as the global, and
// returns both the store and a cleanup hook. Mirrors setupBboltGlobal in
// internal/state but kept local to avoid a cross-package test helper.
func setupPluginStore(t *testing.T) *store.DB {
	t.Helper()
	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prev := store.Global()
	store.SetGlobal(sdb)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = sdb.Close()
	})
	return sdb
}

// TestRefreshPluginCacheTimeoutDoesNotDoubleLog is the regression guard for
// the "Command timed out: su [...]" / "JSON parse failed: unexpected end of
// JSON input" pair that used to fire for the same hung wp-cli call.
//
// With the stdout-only runner surfacing context.DeadlineExceeded, the timeout
// is counted as a timeout, the parser is skipped, and the refresh logs a
// single aggregated summary. Refresh timestamp stays unset because sc == 0.
func TestRefreshPluginCacheTimeoutDoesNotDoubleLog(t *testing.T) {
	sdb := setupPluginStore(t)

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			// Match findAllWPInstalls()'s "/home/*/*/wp-config.php" pattern.
			if pattern == "/home/*/*/wp-config.php" {
				return []string{"/home/alice/www/wp-config.php"}, nil
			}
			return nil, nil
		},
	})

	var wpCalls atomic.Int32
	withMockCmd(t, &mockCmd{
		runContextStdout: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			wpCalls.Add(1)
			return nil, context.DeadlineExceeded
		},
	})

	stderr := captureStderr(t, func() {
		refreshPluginCache(context.Background(), sdb)
	})

	if wpCalls.Load() == 0 {
		t.Fatal("expected wp-cli mock to be invoked at least once")
	}
	if strings.Contains(stderr, "unexpected end of JSON input") {
		t.Errorf("timeout leaked into JSON parser: %q", stderr)
	}
	if !strings.Contains(stderr, "refresh failed") {
		t.Errorf("expected aggregated summary, got %q", stderr)
	}
	if !strings.Contains(stderr, "timeout=") {
		t.Errorf("aggregated summary should report timeout count, got %q", stderr)
	}
	if !sdb.GetPluginRefreshTime().IsZero() {
		t.Error("refresh timestamp must not advance when every site timed out")
	}
}

// TestRefreshPluginCacheDropsStderrFromStdout guards the "invalid character
// 'W'/'P'/'N' looking for beginning of value" class. The production code uses
// RunContextStdout so kernel-level stream separation makes pollution
// impossible. This test pins the contract: given valid JSON on stdout,
// plugins are cached; garbage on stderr is irrelevant (the mock returns only
// what the real exec.Cmd.Output() would return -- stdout bytes).
func TestRefreshPluginCacheDropsStderrFromStdout(t *testing.T) {
	sdb := setupPluginStore(t)

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			// Match findAllWPInstalls()'s "/home/*/*/wp-config.php" pattern.
			if pattern == "/home/*/*/wp-config.php" {
				return []string{"/home/alice/www/wp-config.php"}, nil
			}
			return nil, nil
		},
	})

	withMockCmd(t, &mockCmd{
		runContextStdout: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "plugin list") {
				return []byte(`[{"name":"elementor","status":"active","version":"3.0.0","update_version":"4.0.1"}]`), nil
			}
			if strings.Contains(joined, "option get siteurl") {
				return []byte("https://alice.test\n"), nil
			}
			return nil, nil
		},
	})

	refreshPluginCache(context.Background(), sdb)

	all := sdb.AllSitePlugins()
	site, ok := all["/home/alice/www"]
	if !ok {
		t.Fatalf("expected cache entry for /home/alice/www, got keys=%v", keysOf(all))
	}
	if site.Domain != "alice.test" {
		t.Errorf("domain should not be polluted by stderr, got %q", site.Domain)
	}
	if len(site.Plugins) != 1 || site.Plugins[0].Slug != "elementor" {
		t.Errorf("plugins not parsed, got %+v", site.Plugins)
	}
}

func keysOf(m map[string]store.SitePlugins) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
