package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// On a systemd-resolved host /etc/resolv.conf names only the local stub
// (127.0.0.53); the real upstreams live in /run/systemd/resolve/resolv.conf
// and resolved itself opens TCP connections to them. Both the resolved
// process and any client reaching a configured upstream were reported as
// "non-configured resolver".
func setupResolvedFixtures(t *testing.T, procTCP string) {
	t.Helper()
	tmp := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(tmp, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	procPath := write("proc_net_tcp", procTCP)
	stubPath := write("resolv.conf", "nameserver 127.0.0.53\noptions edns0 trust-ad\n")
	upstreamPath := write("resolved.conf", "# This is /run/systemd/resolve/resolv.conf\nnameserver 203.0.113.53\n")
	passwdPath := write("passwd", "root:x:0:0::/:/bin/sh\nsystemd-resolve:x:193:193:systemd Resolver:/:/sbin/nologin\n")

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
			switch name {
			case "/etc/resolv.conf":
				return os.Open(stubPath)
			case "/run/systemd/resolve/resolv.conf":
				return os.Open(upstreamPath)
			}
			return nil, os.ErrNotExist
		},
	})
}

const (
	procHeader        = "  sl  local_address rem_address   st ...\n"
	upstreamResolver  = "357100CB:0035" // 203.0.113.53:53
	unrelatedResolver = "016433C6:0035" // 198.51.100.1:53
)

func TestCheckDNSConnectionsHonoursResolvedUpstreams(t *testing.T) {
	setupResolvedFixtures(t, procHeader+tcpRow(upstreamResolver, "01", "1000")+"\n")
	if got := CheckDNSConnections(context.Background(), &config.Config{}, nil); len(got) != 0 {
		t.Fatalf("connection to a systemd-resolved upstream reported: %+v", got)
	}
}

func TestCheckDNSConnectionsSkipsResolvedProcess(t *testing.T) {
	setupResolvedFixtures(t, procHeader+tcpRow(unrelatedResolver, "01", "193")+"\n")
	if got := CheckDNSConnections(context.Background(), &config.Config{}, nil); len(got) != 0 {
		t.Fatalf("systemd-resolved's own upstream query reported: %+v", got)
	}
}

func TestCheckDNSConnectionsStillFlagsUnlistedResolverOnResolvedHost(t *testing.T) {
	setupResolvedFixtures(t, procHeader+tcpRow(unrelatedResolver, "01", "1000")+"\n")
	got := CheckDNSConnections(context.Background(), &config.Config{}, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding for an unlisted resolver, got %+v", got)
	}
}
