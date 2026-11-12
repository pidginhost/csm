package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/stalwartapi"
)

// stalwartServiceUsers are the accounts Stalwart's packages run it as.
var stalwartServiceUsers = []string{"stalwart", "stalwart-mail"}

// defaultCheckStalwartListener refuses a local API address whose port is
// held by anyone but root or Stalwart's service user.
func defaultCheckStalwartListener(rawURL string) error {
	return checkStalwartListener("/proc/net", rawURL, lookupUIDs)
}

func lookupUIDs(names ...string) []uint32 {
	var out []uint32
	for _, name := range names {
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		if uid, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
			out = append(out, uint32(uid))
		}
	}
	return out
}

// checkStalwartListener runs before the admin login is sent to an address on
// this host. Any local user can listen on an unprivileged port while
// Stalwart is down and collect the login, so every listening socket on the
// API port must belong to root or Stalwart's service user. A remote address
// is protected by TLS instead.
func checkStalwartListener(procNet, rawURL string, uidsOf func(names ...string) []uint32) error {
	if !stalwartapi.LocalURL(rawURL) {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return fmt.Errorf("API port %q is not a number", p)
		}
	}
	var owners []uint32
	for _, name := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(procNet, name)) // #nosec G304 -- fixed /proc paths
		if errors.Is(err, os.ErrNotExist) && name == "tcp6" {
			continue // IPv6 may be disabled in the kernel.
		}
		if err != nil {
			return fmt.Errorf("cannot inspect %s sockets: %w", name, err)
		}
		found, readErr := listenOwners(f, port)
		_ = f.Close()
		if readErr != nil {
			return fmt.Errorf("cannot inspect %s sockets: %w", name, readErr)
		}
		owners = append(owners, found...)
	}
	if len(owners) == 0 {
		return fmt.Errorf("nothing on this host listens on port %d; is Stalwart running?", port)
	}
	allowed := append([]uint32{0}, uidsOf(stalwartServiceUsers...)...)
	for _, uid := range owners {
		if !slices.Contains(allowed, uid) {
			return fmt.Errorf("port %d is held by uid %d, not root or Stalwart's service user", port, uid)
		}
	}
	return nil
}

// listenOwners returns the uids of listening TCP sockets on port, read from
// a /proc/net/tcp or tcp6 table.
func listenOwners(r io.Reader, port int) ([]uint32, error) {
	var out []uint32
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[3] != "0A" { // 0A is TCP_LISTEN
			continue
		}
		_, hexPort, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		p, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil || int(p) != port {
			continue
		}
		uid, err := strconv.ParseUint(f[7], 10, 32)
		if err != nil {
			return nil, errors.New("invalid socket owner")
		}
		out = append(out, uint32(uid))
	}
	return out, sc.Err()
}

// A listener check alone races service restarts. Verify the accepted side
// of this connection, not whichever socket now listens on its port.
func checkStalwartPeer(ctx context.Context, conn net.Conn) error {
	local, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return errors.New("cannot identify local API connection")
	}
	remote, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil || !remote.Addr().Unmap().IsLoopback() {
		return errors.New("local API address did not connect to loopback")
	}
	return waitStalwartPeer(ctx, "/proc/net", local, remote, lookupUIDs)
}

func waitStalwartPeer(ctx context.Context, procNet string, local, remote netip.AddrPort, uidsOf func(...string) []uint32) error {
	allowed := append([]uint32{0}, uidsOf(stalwartServiceUsers...)...)
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		for _, name := range []string{"tcp", "tcp6"} {
			f, err := os.Open(filepath.Join(procNet, name)) // #nosec G304 -- fixed /proc paths
			if errors.Is(err, os.ErrNotExist) && name == "tcp6" {
				continue
			}
			if err != nil {
				return fmt.Errorf("cannot inspect API peer: %w", err)
			}
			uid, found, readErr := stalwartPeerOwner(f, local, remote)
			_ = f.Close()
			if readErr != nil {
				return fmt.Errorf("cannot inspect API peer: %w", readErr)
			}
			if found {
				if !slices.Contains(allowed, uid) {
					return fmt.Errorf("API peer is held by uid %d, not root or Stalwart's service user", uid)
				}
				return nil
			}
		}
		// Until accept(), procfs can report uid 0 and inode 0 even for an
		// untrusted listener. Never treat that placeholder as a root peer.
		select {
		case <-ctx.Done():
			return fmt.Errorf("cannot verify accepted API peer: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func stalwartPeerOwner(r io.Reader, local, remote netip.AddrPort) (uint32, bool, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != "01" {
			continue
		}
		server, err := procSocketAddress(f[1])
		if err != nil {
			return 0, false, err
		}
		client, err := procSocketAddress(f[2])
		if err != nil {
			return 0, false, err
		}
		if server != netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port()) ||
			client != netip.AddrPortFrom(local.Addr().Unmap(), local.Port()) {
			continue
		}
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil {
			return 0, false, errors.New("invalid socket inode")
		}
		if inode == 0 {
			continue
		}
		uid, err := strconv.ParseUint(f[7], 10, 32)
		if err != nil {
			return 0, false, errors.New("invalid socket owner")
		}
		return uint32(uid), true, nil
	}
	return 0, false, sc.Err()
}

func procSocketAddress(raw string) (netip.AddrPort, error) {
	host, port, ok := strings.Cut(raw, ":")
	if !ok {
		return netip.AddrPort{}, errors.New("invalid socket address")
	}
	b, err := hex.DecodeString(host)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.AddrPort{}, errors.New("invalid socket address")
	}
	// procfs renders each native-endian 32-bit word as hexadecimal.
	for i := 0; i < len(b); i += 4 {
		word := binary.BigEndian.Uint32(b[i : i+4])
		binary.NativeEndian.PutUint32(b[i:i+4], word)
	}
	ip, _ := netip.AddrFromSlice(b)
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.AddrPort{}, errors.New("invalid socket port")
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(p)), nil
}
