package checks

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/state"
)

// --- CheckLoadAverage with actual /proc data -------------------------

func TestCheckLoadAverageHighLoad(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if name == "/proc/loadavg" {
				return []byte("50.00 40.00 30.00 3/500 12345"), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if name == "/proc/cpuinfo" {
				tmp := t.TempDir() + "/cpuinfo"
				_ = os.WriteFile(tmp, []byte("processor\t: 0\nprocessor\t: 1\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckLoadAverage(context.Background(), &config.Config{}, nil)
	found := false
	for _, f := range findings {
		if f.Check == "perf_load" {
			found = true
		}
	}
	if !found {
		t.Error("high load should produce perf_load finding")
	}
}

// --- CheckOutboundUserConnections with suspicious connection ----------

func TestCheckOutboundUserConnectionsSuspicious(t *testing.T) {
	// Simulate a non-root user with an outbound connection to a non-safe port
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n" +
		"   0: 0100007F:C000 CB007105:2710 01 00000000:00000000 00:00000000 00000000  1000\n"
	// CB007105 = 203.0.113.5, port 2710 = 10000 (non-safe)
	passwdData := "alice:x:1000:1000::/home/alice:/bin/bash\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/net/tcp":
				return []byte(tcpData), nil
			case "/etc/passwd":
				return []byte(passwdData), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckOutboundUserConnections(context.Background(), &config.Config{}, nil)
	if len(findings) == 0 {
		t.Error("suspicious outbound should produce a finding")
	}
}

// --- CheckWPBruteForce with log data ---------------------------------

func TestCheckWPBruteForceDetects(t *testing.T) {
	// Create a fake access log with many wp-login POST requests
	var logLines []string
	for i := 0; i < 15; i++ {
		logLines = append(logLines,
			fmt.Sprintf(`203.0.113.%d - - [12/Apr/2026:10:00:%02d +0000] "POST /wp-login.php HTTP/1.1" 200 1234`,
				i%3+1, i))
	}
	logContent := strings.Join(logLines, "\n") + "\n"

	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if strings.Contains(pattern, "access") || strings.Contains(pattern, "ssl_log") {
				return []string{"/home/alice/access-logs/example.com-ssl_log"}, nil
			}
			return nil, nil
		},
		readFile: func(name string) ([]byte, error) {
			return []byte(logContent), nil
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "example.com-ssl_log", size: int64(len(logContent))}, nil
		},
	})

	findings := CheckWPBruteForce(context.Background(), &config.Config{}, nil)
	_ = findings // exercises the log parsing path
}

// --- RunTier with mocked system calls --------------------------------

func TestRunTierCriticalWithMocks(t *testing.T) {
	withMockOS(t, &mockOS{})
	withMockCmd(t, &mockCmd{})

	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Firewall = &firewall.FirewallConfig{}
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	// Run critical tier — all checks should handle empty mocks gracefully.
	findings := RunTier(cfg, store, TierCritical)
	// Just verify it doesn't panic.
	_ = findings
}

// --- RunAll with mocked system calls ---------------------------------

func TestRunAllWithMocks(t *testing.T) {
	withMockOS(t, &mockOS{})
	withMockCmd(t, &mockCmd{})
	ForceAll = true
	defer func() { ForceAll = false }()

	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Firewall = &firewall.FirewallConfig{}
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := RunAll(cfg, store)
	_ = findings
}

// --- RunReducedDeep with mocked system calls -------------------------

func TestRunReducedDeepWithMocks(t *testing.T) {
	withMockOS(t, &mockOS{})
	withMockCmd(t, &mockCmd{})

	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Firewall = &firewall.FirewallConfig{}
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	findings := RunReducedDeep(cfg, store)
	_ = findings
}

// --- AutoFixPermissions with mock ------------------------------------

func TestAutoFixPermissionsNoFindings(t *testing.T) {
	cfg := &config.Config{}
	actions, keys := AutoFixPermissions(cfg, nil)
	if len(actions) != 0 || len(keys) != 0 {
		t.Errorf("nil should produce 0, got %d actions %d keys", len(actions), len(keys))
	}
}

func TestAutoFixPermissionsEmptyFindings(t *testing.T) {
	cfg := &config.Config{}
	actions, keys := AutoFixPermissions(cfg, []alert.Finding{})
	if len(actions) != 0 || len(keys) != 0 {
		t.Errorf("empty should produce 0, got %d actions %d keys", len(actions), len(keys))
	}
}
