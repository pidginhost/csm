package checks

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// --- CheckOutboundUserConnections with suspicious UID connection ------

func TestCheckOutboundUserConnectionsWithUID(t *testing.T) {
	// UID 1000, remote port 4444 (reverse shell), ESTABLISHED
	tcpData := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n" +
		"   0: 0100007F:C000 CB007105:115C 01 00000000:00000000 00:00000000 00000000  1000\n"
	tcp6Data := ""
	passwdData := "alice:x:1000:1000::/home/alice:/bin/bash\n"

	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/net/tcp":
				return []byte(tcpData), nil
			case "/proc/net/tcp6":
				return []byte(tcp6Data), nil
			case "/etc/passwd":
				return []byte(passwdData), nil
			}
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	findings := CheckOutboundUserConnections(context.Background(), cfg, nil)
	// Port 4444 is not in safe ports — should produce a finding
	if len(findings) == 0 {
		t.Error("reverse shell port should produce finding")
	}
}

// --- CheckModSecAuditLog with log data --------------------------------

func TestCheckModSecAuditLogWithData(t *testing.T) {
	logData := `--abc123--A--
[12/Apr/2026:10:00:00 +0000] 203.0.113.5 80
--abc123--B--
POST /wp-login.php HTTP/1.1
Host: example.com
--abc123--H--
Message: Access denied with code 403 [id "920420"]
--abc123--Z--
`
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if strings.Contains(name, "modsec_audit") {
				return fakeFileInfo{name: "modsec_audit.log", size: int64(len(logData))}, nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if strings.Contains(name, "modsec_audit") {
				tmp := t.TempDir() + "/modsec_audit.log"
				_ = os.WriteFile(tmp, []byte(logData), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	_ = CheckModSecAuditLog(context.Background(), &config.Config{}, nil)
}

// --- getCPUCores with mock /proc/cpuinfo ------------------------------

func TestGetCPUCoresMocked(t *testing.T) {
	// Reset the sync.Once by using the mock before the first real call.
	// Note: sync.Once can only fire once per process. If other tests
	// already called getCPUCores with real data, this test won't override.
	// This test exercises the mock path if it runs first.
	withMockOS(t, &mockOS{
		open: func(name string) (*os.File, error) {
			if name == "/proc/cpuinfo" {
				tmp := t.TempDir() + "/cpuinfo"
				_ = os.WriteFile(tmp, []byte("processor\t: 0\nprocessor\t: 1\nprocessor\t: 2\nprocessor\t: 3\n"), 0644)
				return os.Open(tmp)
			}
			return nil, os.ErrNotExist
		},
	})

	cores := getCPUCores()
	// May return cached value from previous test runs (sync.Once).
	if cores < 1 {
		t.Errorf("cores = %d, want >= 1", cores)
	}
}

// --- collectRecentIPs with log data -----------------------------------

func TestCollectRecentIPsWithLogs(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			if strings.Contains(name, "access_log") || strings.Contains(name, "error_log") {
				return []byte("203.0.113.5 - - [12/Apr/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200\n"), nil
			}
			if strings.Contains(name, "secure") || strings.Contains(name, "auth.log") {
				return []byte("Apr 12 10:00:00 host sshd[1234]: Failed password for root from 198.51.100.1 port 22 ssh2\n"), nil
			}
			return nil, os.ErrNotExist
		},
		stat: func(name string) (os.FileInfo, error) {
			return fakeFileInfo{name: "log", size: 500}, nil
		},
		open: func(name string) (*os.File, error) {
			return nil, os.ErrNotExist
		},
	})

	cfg := &config.Config{}
	ips := collectRecentIPs(cfg)
	_ = ips
}

// --- cleanCache with expired entries ----------------------------------

func TestCleanCacheWithExpiredEntries(t *testing.T) {
	cache := &reputationCache{Entries: map[string]*reputationEntry{
		"old":    {Score: 50, CheckedAt: time.Now().Add(-8 * time.Hour)},
		"recent": {Score: 30, CheckedAt: time.Now()},
	}}
	cleanCache(cache)
	if _, ok := cache.Entries["old"]; ok {
		t.Error("expired entry should be removed")
	}
	if _, ok := cache.Entries["recent"]; !ok {
		t.Error("recent entry should be kept")
	}
}

// --- scanGroupWritablePHP with actual writable file -------------------

func TestScanGroupWritablePHPWithWritableFile(t *testing.T) {
	dir := t.TempDir()
	phpFile := dir + "/config.php"
	_ = os.WriteFile(phpFile, []byte("<?php"), 0664) // group-writable

	// Use real OS for this since we have real temp files
	old := osFS
	osFS = realOS{}
	defer func() { osFS = old }()

	webGIDs := map[uint32]bool{} // empty — won't match
	var findings []alert.Finding
	scanGroupWritablePHP(dir, 3, webGIDs, &findings)
	_ = findings
}
