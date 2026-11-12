//go:build linux

package main

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"
)

// Exercise the kernel representation too: the peer can accept an IPv4
// connection through a dual-stack IPv6 socket.
func TestStalwartPeerKernelOwnership(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6", "tcp", "tcp6-zone"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network != "tcp4" {
				address = "[::]:0"
			}
			listenNetwork := network
			if network == "tcp6-zone" {
				listenNetwork = "tcp6"
			}
			listener, err := net.Listen(listenNetwork, address)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			port := listener.Addr().(*net.TCPAddr).Port
			host := "127.0.0.1"
			if listenNetwork == "tcp6" {
				host = "::1"
			}
			if network == "tcp6-zone" {
				host = "::1%lo"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			local := netip.MustParseAddrPort(conn.LocalAddr().String())
			remote := netip.MustParseAddrPort(conn.RemoteAddr().String())
			if err := waitStalwartPeer(ctx, "/proc/net", local, remote, func(...string) []uint32 {
				return []uint32{uint32(os.Getuid())} // #nosec G115 -- Linux UIDs fit uint32
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
