package main

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

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
		if err != nil {
			continue
		}
		owners = append(owners, listenOwners(f, port)...)
		_ = f.Close()
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
func listenOwners(r io.Reader, port int) []uint32 {
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
		if uid, err := strconv.ParseUint(f[7], 10, 32); err == nil {
			out = append(out, uint32(uid))
		}
	}
	return out
}
