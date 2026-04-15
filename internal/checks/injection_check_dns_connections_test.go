package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// Helper: build a /proc/net/tcp row. Layout:
//
//	 sl  local_address rem_address st ... uid ...
//
// We control local_address (any), remote_address (hex ip:port), st, uid.
func tcpRow(remHex, state, uid string) string {
	// Columns 0-9 space-separated. /proc/net/tcp has 12+ columns; we fill
	// only what CheckDNSConnections reads: [1]=local, [2]=rem, [3]=state,
	// [7]=uid. Pad out to that offset with filler.
	return "   0: 0100007F:ABCD " + remHex + " " + state + " 00000000:00000000 00:00000000 00000000 " + uid + "        0 0 0 0"
}

func setupDNSConnectionsFixtures(t *testing.T, procTCP string, resolvConf string, passwd string) {
	t.Helper()
	tmp := t.TempDir()
	procPath := filepath.Join(tmp, "proc_net_tcp")
	resolvPath := filepath.Join(tmp, "resolv.conf")
	passwdPath := filepath.Join(tmp, "passwd")
	if err := os.WriteFile(procPath, []byte(procTCP), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolvPath, []byte(resolvConf), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwdPath, []byte(passwd), 0644); err != nil {
		t.Fatal(err)
	}
	withMockOS(t, &mockOS{
		readFile: func(name string) ([]byte, error) {
			switch name {
			case "/proc/net/tcp":
				return os.ReadFile(procPath)
			case "/etc/passwd":
				return os.ReadFile(passwdPath)
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if name == "/etc/resolv.conf" {
				return os.Open(resolvPath)
			}
			return nil, os.ErrNotExist
		},
	})
}

func TestCheckDNSConnectionsNoResolversReturnsNil(t *testing.T) {
	// resolv.conf missing → parseResolvers returns nil → function short-circuits.
	withMockOS(t, &mockOS{})
	got := CheckDNSConnections(context.Background(), &config.Config{}, nil)
	if got != nil {
		t.Errorf("missing resolv.conf should yield nil, got %d findings", len(got))
	}
}

func TestCheckDNSConnectionsProcReadFailReturnsNil(t *testing.T) {
	setupDNSConnectionsFixtures(t,
		"", // no /proc/net/tcp content — but we only mock the path to exist, not the contents
		"nameserver 1.1.1.1\n",
		"root:x:0:0:root:/root:/bin/bash\n",
	)
	// Overwrite mock to fail /proc/net/tcp.
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		open: func(name string) (*os.File, error) {
			if name == "/etc/resolv.conf" {
				tmp, _ := os.CreateTemp(t.TempDir(), "resolv")
				_, _ = tmp.WriteString("nameserver 1.1.1.1\n")
				_, _ = tmp.Seek(0, 0)
				return tmp, nil
			}
			return nil, os.ErrNotExist
		},
	})
	got := CheckDNSConnections(context.Background(), &config.Config{}, nil)
	if got != nil {
		t.Errorf("unreadable /proc/net/tcp should yield nil, got %d findings", len(got))
	}
}

func TestCheckDNSConnectionsConfiguredResolverSkipped(t *testing.T) {
	// 1.1.1.1 = 0x01010101 in little-endian hex as stored in /proc/net/tcp.
	// /proc/net/tcp writes 32-bit IPs as big-endian hex of the little-
	// endian byte order: 1.1.1.1 → "01010101".
	// Port 53 = 0x0035.
	rem := "01010101:0035" // 1.1.1.1:53
	proc := "  sl  local_address rem_address   st ...\n" +
		tcpRow(rem, "01", "1000") + "\n"
	setupDNSConnectionsFixtures(t, proc, "nameserver 1.1.1.1\n", "root:x:0:0::/:/bin/sh\n")

	got := CheckDNSConnections(context.Background(), &config.Config{}, nil)
	if len(got) != 0 {
		t.Errorf("configured resolver should be skipped, got %+v", got)
	}
}

func TestCheckDNSConnectionsUnlistedResolverEmitsFinding(t *testing.T) {
	// 8.8.4.4:53 in hex is "04040808:0035"
	rem := "04040808:0035" // 8.8.4.4:53 (little-endian in /proc/net/tcp)
	proc := "  sl  local_address rem_address   st ...\n" +
		tcpRow(rem, "01", "1000") + "\n"
	setupDNSConnectionsFixtures(t, proc, "nameserver 1.1.1.1\n", "root:x:0:0::/:/bin/sh\n")

	got := CheckDNSConnections(context.Background(), &config.Config{}, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Check != "dns_connection" || got[0].Severity != alert.High {
		t.Errorf("unexpected finding: %+v", got[0])
	}
	if got[0].Message == "" || got[0].Details == "" {
		t.Errorf("finding should carry populated message and details: %+v", got[0])
	}
}

func TestCheckDNSConnectionsDNSServerProcessSkipped(t *testing.T) {
	// Same unlisted resolver, but owned by UID 25 (named in our passwd).
	rem := "04040808:0035" // 8.8.4.4:53 (little-endian in /proc/net/tcp)
	proc := "  sl  local_address rem_address   st ...\n" +
		tcpRow(rem, "01", "25") + "\n"
	setupDNSConnectionsFixtures(t, proc,
		"nameserver 1.1.1.1\n",
		"root:x:0:0::/:/bin/sh\nnamed:x:25:25::/var/named:/sbin/nologin\n",
	)

	got := CheckDNSConnections(context.Background(), &config.Config{}, nil)
	if len(got) != 0 {
		t.Errorf("named-owned connection should be skipped, got %+v", got)
	}
}

func TestCheckDNSConnectionsInfraIPSkipped(t *testing.T) {
	rem := "04040808:0035" // 8.8.4.4:53 (little-endian in /proc/net/tcp) // 8.8.4.4:53
	proc := "  sl  local_address rem_address   st ...\n" +
		tcpRow(rem, "01", "1000") + "\n"
	setupDNSConnectionsFixtures(t, proc, "nameserver 1.1.1.1\n", "root:x:0:0::/:/bin/sh\n")

	// 8.8.4.4 is in our "infra" list → finding must be suppressed.
	got := CheckDNSConnections(context.Background(), &config.Config{InfraIPs: []string{"8.8.4.4"}}, nil)
	if len(got) != 0 {
		t.Errorf("infra IP should be skipped, got %+v", got)
	}
}

func TestCheckDNSConnectionsNonEstablishedStateIgnored(t *testing.T) {
	// State "06" = TIME_WAIT; must be ignored.
	rem := "04040808:0035" // 8.8.4.4:53 (little-endian in /proc/net/tcp)
	proc := "  sl  local_address rem_address   st ...\n" +
		tcpRow(rem, "06", "1000") + "\n"
	setupDNSConnectionsFixtures(t, proc, "nameserver 1.1.1.1\n", "root:x:0:0::/:/bin/sh\n")

	got := CheckDNSConnections(context.Background(), &config.Config{}, nil)
	if len(got) != 0 {
		t.Errorf("non-established connection should be ignored, got %+v", got)
	}
}

func TestCheckDNSConnectionsWrongPortIgnored(t *testing.T) {
	// Port 443 not 53.
	rem := "04040808:01BB" // 8.8.4.4:443
	proc := "  sl  local_address rem_address   st ...\n" +
		tcpRow(rem, "01", "1000") + "\n"
	setupDNSConnectionsFixtures(t, proc, "nameserver 1.1.1.1\n", "root:x:0:0::/:/bin/sh\n")

	got := CheckDNSConnections(context.Background(), &config.Config{}, nil)
	if len(got) != 0 {
		t.Errorf("non-port-53 connection should be ignored, got %+v", got)
	}
}
