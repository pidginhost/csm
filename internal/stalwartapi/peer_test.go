package stalwartapi

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

const procNetTCPFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   997        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1001        0 2 1 0000000000000000 20 4 30 10 -1
   2: 00000000:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
`

func TestListenOwners(t *testing.T) {
	got, err := listenOwners(strings.NewReader(procNetTCPFixture), 8080)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []uint32{997}) {
		t.Fatalf("owners of 8080 = %v, want only the listening socket's uid 997", got)
	}
	if got, err := listenOwners(strings.NewReader(procNetTCPFixture), 25); err != nil || !reflect.DeepEqual(got, []uint32{0}) {
		t.Fatalf("owners of 25 = %v", got)
	}
}

func TestCheckStalwartListener(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/tcp", []byte(procNetTCPFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/tcp6", []byte("  sl header\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stalwartUID := func(names ...string) []uint32 { return []uint32{997} }
	if err := checkStalwartListener(dir, "http://127.0.0.1:8080", stalwartUID); err != nil {
		t.Fatalf("Stalwart's own listener refused: %v", err)
	}
	other := func(names ...string) []uint32 { return []uint32{996} }
	if err := checkStalwartListener(dir, "http://127.0.0.1:8080", other); err == nil || !strings.Contains(err.Error(), "997") {
		t.Fatalf("foreign listener: err = %v, want a refusal naming uid 997", err)
	}
	if err := checkStalwartListener(dir, "http://127.0.0.1:9090", stalwartUID); err == nil {
		t.Fatal("a port nothing listens on was accepted")
	}
	if err := checkStalwartListener(dir, "https://mail.example.org", other); err != nil {
		t.Fatalf("remote https address checked against local sockets: %v", err)
	}
}

func TestCheckStalwartListenerFailsClosedOnIncompleteTables(t *testing.T) {
	for _, mode := range []string{"open error", "unreadable", "truncated", "invalid owner"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(dir+"/tcp", []byte(procNetTCPFixture), 0o600); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "open error":
				if err := os.Symlink("tcp6", dir+"/tcp6"); err != nil {
					t.Fatal(err)
				}
			case "unreadable":
				if err := os.Mkdir(dir+"/tcp6", 0o700); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.WriteFile(dir+"/tcp6", []byte(strings.Repeat("x", 65536)), 0o600); err != nil {
					t.Fatal(err)
				}
			case "invalid owner":
				if err := os.WriteFile(dir+"/tcp6", []byte(strings.ReplaceAll(procNetTCPFixture, "997", "invalid")), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := checkStalwartListener(dir, "http://127.0.0.1:8080", func(...string) []uint32 { return []uint32{997} }); err == nil {
				t.Fatal("incomplete socket ownership evidence allowed the login")
			}
		})
	}
}

func TestStalwartPeerOwnerMatchesConnectedSocket(t *testing.T) {
	client := netip.MustParseAddrPort("127.0.0.1:54321")
	server := netip.MustParseAddrPort("127.0.0.1:8080")
	row := func(local, remote, uid, inode string) string {
		return fmt.Sprintf("0: %s %s 01 00000000:00000000 00:00000000 00000000 %s 0 %s\n", local, remote, uid, inode)
	}
	v4 := fmt.Sprintf("%08X", binary.NativeEndian.Uint32([]byte{127, 0, 0, 1}))
	v6 := fmt.Sprintf("%08X%08X%08X%08X", 0, 0, binary.NativeEndian.Uint32([]byte{0, 0, 255, 255}), binary.NativeEndian.Uint32([]byte{127, 0, 0, 1}))
	for _, tc := range []struct {
		name, data string
		found      bool
		uid        uint32
		bad        bool
	}{
		{"accepted", row(v4+":1F90", v4+":D431", "997", "123"), true, 997, false},
		{"mapped IPv6", row(v6+":1F90", v6+":D431", "997", "123"), true, 997, false},
		{"client side", row(v4+":D431", v4+":1F90", "0", "124"), false, 0, false},
		{"other connection", row(v4+":1F90", v4+":D432", "0", "125"), false, 0, false},
		{"not accepted", row(v4+":1F90", v4+":D431", "0", "0"), false, 0, false},
		{"foreign accepted", row(v4+":1F90", v4+":D431", "1001", "123"), true, 1001, false},
		{"invalid owner", row(v4+":1F90", v4+":D431", "invalid", "123"), false, 0, true},
		{"truncated", strings.Repeat("x", 65536), false, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid, found, err := stalwartPeerOwner(strings.NewReader(tc.data), client, server)
			if uid != tc.uid || found != tc.found || (err != nil) != tc.bad {
				t.Fatalf("uid=%d found=%v err=%v", uid, found, err)
			}
		})
	}
}

func TestWaitStalwartPeerUsesAcceptedOwner(t *testing.T) {
	local := netip.MustParseAddrPort("127.0.0.1:54321")
	remote := netip.MustParseAddrPort("127.0.0.1:8080")
	for _, tc := range []struct {
		name, uid, inode string
		allowed          bool
	}{
		{"trusted", "997", "123", true},
		{"root", "0", "123", true},
		{"foreign", "1001", "123", false},
		{"unaccepted", "0", "0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ip := fmt.Sprintf("%08X", binary.NativeEndian.Uint32([]byte{127, 0, 0, 1}))
			data := strings.ReplaceAll(procNetTCPFixture, "0100007F:D431", "0100007F:D432") + fmt.Sprintf("4: %s:1F90 %s:D431 01 0:0 00:0 0 %s 0 %s\n", ip, ip, tc.uid, tc.inode)
			if err := os.WriteFile(dir+"/tcp", []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.inode == "0" {
				cancel()
			}
			err := waitStalwartPeer(ctx, dir, local, remote, func(...string) []uint32 { return []uint32{997} })
			if (err == nil) != tc.allowed {
				t.Fatalf("accepted=%v: %v", err == nil, err)
			}
		})
	}
}
