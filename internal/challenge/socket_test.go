package challenge

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/netutil"
)

// shortSocketDir keeps socket paths under the 108-byte sun_path limit, which
// t.TempDir under a long test name can exceed.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(d, 0o700)
		_ = os.RemoveAll(d)
	})
	return d
}

func ownGroup(t *testing.T) (string, uint32) {
	t.Helper()
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skipf("own group not resolvable: %v", err)
	}
	return g.Name, uint32(os.Getgid()) // #nosec G115 -- test gid
}

func socketCfg(path, group string) *config.Config {
	cfg := baseCfg()
	cfg.Challenge.ListenAddr = "unix:" + path
	cfg.Challenge.ListenGroup = group
	return cfg
}

func socketClient(path string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}},
	}
}

func serveSocket(t *testing.T, cfg *config.Config, list *IPList) *Server {
	t.Helper()
	s := New(cfg, list)
	ln, err := s.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(s.Shutdown)
	return s
}

func gateStatus(t *testing.T, path, xff string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://csm-challenge/challenge/gate", nil)
	if err != nil {
		t.Fatal(err)
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := socketClient(path).Do(req)
	if err != nil {
		t.Fatalf("gate request: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestListenRefusesHostLocalTrustedProxy(t *testing.T) {
	group, _ := ownGroup(t)
	for _, entry := range []string{"127.0.0.1", "203.0.113.0/24"} {
		for _, socket := range []bool{false, true} {
			t.Run(entry+"/socket="+strconv.FormatBool(socket), func(t *testing.T) {
				cfg := baseCfg()
				cfg.Challenge.ListenAddr = "127.0.0.1"
				dir := shortSocketDir(t)
				if socket {
					cfg = socketCfg(filepath.Join(dir, "c.sock"), group)
				}
				cfg.Challenge.TrustedProxies = []string{"198.51.100.2", entry}
				ln, err := New(cfg, nil).Listen()
				if ln != nil {
					_ = ln.Close()
					t.Fatal("listener bound despite host-local trust")
				}
				if err == nil || !strings.Contains(err.Error(), entry) || !strings.Contains(err.Error(), config.ChallengeSocketExample) {
					t.Fatalf("err = %v, want refusal naming %q and the socket", err, entry)
				}
				if got := leftovers(t, dir); len(got) != 0 {
					t.Fatalf("refusal left %v behind", got)
				}
			})
		}
	}
}

func pinHost(t *testing.T, addrs ...string) {
	t.Helper()
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) {
		out := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, net.ParseIP(a))
		}
		return out, nil
	}))
}

func TestTrustedPeerAddedToHostIsNotTrusted(t *testing.T) {
	trusted := []string{"198.51.100.0/24"}
	if got := extractVia(t, trusted, "198.51.100.9:1234", "192.0.2.50"); got != "192.0.2.50" {
		t.Fatalf("control: remote proxy gave %q, want the visitor", got)
	}
	pinHost(t, testHostAddr, "198.51.100.9")
	if got := extractVia(t, trusted, "198.51.100.9:1234", "192.0.2.50"); got != "198.51.100.9" {
		t.Fatalf("host-local peer gave %q, want its own address", got)
	}
}

func TestHostLocalHopEndsForwardedWalk(t *testing.T) {
	trusted := []string{"198.51.100.0/24"}
	if got := extractVia(t, trusted, "198.51.100.2:1234", "192.0.2.50, 198.51.100.9"); got != "192.0.2.50" {
		t.Fatalf("control: walk gave %q, want the visitor", got)
	}
	pinHost(t, testHostAddr, "198.51.100.9")
	if got := extractVia(t, trusted, "198.51.100.2:1234", "192.0.2.50, 198.51.100.9"); got != "198.51.100.9" {
		t.Fatalf("walk past a host-local hop gave %q, want the hop", got)
	}
}

func TestUnknownHostSetTrustsNoPeer(t *testing.T) {
	t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) { return nil, errors.New("netlink down") }))
	if got := extractVia(t, []string{"198.51.100.2"}, "198.51.100.2:1234", "192.0.2.50"); got != "198.51.100.2" {
		t.Fatalf("unknown host set gave %q, want the peer itself", got)
	}
}

func TestSocketServesVisitorFromForwardedFor(t *testing.T) {
	group, _ := ownGroup(t)
	path := filepath.Join(shortSocketDir(t), "c.sock")
	list := NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
	list.Add("192.0.2.60", "test", time.Hour)
	s := serveSocket(t, socketCfg(path, group), list)
	if s.Addr() != path {
		t.Fatalf("Addr = %q, want %q", s.Addr(), path)
	}
	if code := gateStatus(t, path, "192.0.2.60"); code != http.StatusUnauthorized {
		t.Fatalf("listed visitor: %d, want 401", code)
	}
	if code := gateStatus(t, path, "192.0.2.61"); code != http.StatusNoContent {
		t.Fatalf("unlisted visitor: %d, want 204", code)
	}
}

func TestSocketWithoutForwardedForIs400(t *testing.T) {
	group, _ := ownGroup(t)
	path := filepath.Join(shortSocketDir(t), "c.sock")
	serveSocket(t, socketCfg(path, group), NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt")))
	for _, xff := range []string{"", "garbage"} {
		if code := gateStatus(t, path, xff); code != http.StatusBadRequest {
			t.Fatalf("X-Forwarded-For %q: %d, want 400", xff, code)
		}
	}
}

func TestSocketTrustedForwardedChain(t *testing.T) {
	group, _ := ownGroup(t)
	for _, tc := range []struct {
		name, xff, listed string
		local             bool
		unknown           bool
		status            int
	}{
		{"visitor", "192.0.2.60, 198.51.100.2", "192.0.2.60", false, false, http.StatusUnauthorized},
		{"all proxies", "198.51.100.9, 198.51.100.2", "", false, false, http.StatusBadRequest},
		{"unreadable hop", "192.0.2.60, unknown, 198.51.100.2", "192.0.2.60", false, false, http.StatusBadRequest},
		{"local hop", "192.0.2.60, 198.51.100.9, 198.51.100.2", "198.51.100.9", true, false, http.StatusUnauthorized},
		{"unknown host set", "192.0.2.60, 198.51.100.2", "198.51.100.2", false, true, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(shortSocketDir(t), "c.sock")
			cfg := socketCfg(path, group)
			cfg.Challenge.TrustedProxies = []string{"198.51.100.0/24"}
			list := NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt"))
			if tc.listed != "" {
				list.Add(tc.listed, "test", time.Hour)
			}
			serveSocket(t, cfg, list)
			if tc.local {
				pinHost(t, testHostAddr, "198.51.100.9")
			}
			if tc.unknown {
				t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) { return nil, errors.New("netlink down") }))
			}
			if code := gateStatus(t, path, tc.xff); code != tc.status {
				t.Fatalf("gate = %d, want %d", code, tc.status)
			}
		})
	}
}

func TestSocketFileModeAndGroup(t *testing.T) {
	group, gid := ownGroup(t)
	path := filepath.Join(shortSocketDir(t), "c.sock")
	serveSocket(t, socketCfg(path, group), nil)
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o660 {
		t.Fatalf("mode = %v, want socket 0660", fi.Mode())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Gid != gid {
		t.Fatalf("gid = %v, want %d", fi.Sys(), gid)
	}
}

func TestSocketReplacesStaleSocket(t *testing.T) {
	group, _ := ownGroup(t)
	path := filepath.Join(shortSocketDir(t), "c.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	_ = stale.Close()
	serveSocket(t, socketCfg(path, group), nil)
	if code := gateStatus(t, path, "192.0.2.61"); code != http.StatusNoContent {
		t.Fatalf("after replacing stale socket: %d, want 204", code)
	}
}

func TestSocketRefusesNonSocketFile(t *testing.T) {
	group, _ := ownGroup(t)
	path := filepath.Join(shortSocketDir(t), "c.sock")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ln, err := New(socketCfg(path, group), nil).Listen(); err == nil {
		_ = ln.Close()
		t.Fatal("bound over a regular file")
	}
	if b, _ := os.ReadFile(path); string(b) != "keep" {
		t.Fatalf("regular file changed to %q", b)
	}
}

func TestSocketRefusesWritableParent(t *testing.T) {
	group, _ := ownGroup(t)
	for _, mode := range []os.FileMode{0o770, 0o757} {
		dir := shortSocketDir(t)
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		ln, err := New(socketCfg(filepath.Join(dir, "c.sock"), group), nil).Listen()
		if err == nil {
			_ = ln.Close()
			t.Fatalf("parent %v: bound, want refusal", mode)
		}
		if !strings.Contains(err.Error(), dir) {
			t.Fatalf("parent %v: err = %v, want it to name %s", mode, err, dir)
		}
	}
}

func TestSocketRefusesUnknownGroup(t *testing.T) {
	dir := shortSocketDir(t)
	ln, err := New(socketCfg(filepath.Join(dir, "c.sock"), "csm-no-such-group"), nil).Listen()
	if err == nil {
		_ = ln.Close()
		t.Fatal("bound with an unknown group")
	}
	if !strings.Contains(err.Error(), "csm-no-such-group") {
		t.Fatalf("err = %v, want it to name the group", err)
	}
	if got := leftovers(t, dir); len(got) != 0 {
		t.Fatalf("refusal left %v behind", got)
	}
}

func TestSocketRefusesTooLongPath(t *testing.T) {
	group, _ := ownGroup(t)
	dir := shortSocketDir(t)
	// The final path fits sun_path, but the bind-time name inside the
	// parent would not.
	deep := dir
	for len(deep) < 95 {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := New(socketCfg(filepath.Join(deep, "c"), group), nil).Listen()
	if err == nil {
		_ = ln.Close()
		t.Fatal("bound a path whose bind-time name exceeds sun_path")
	}
	if !strings.Contains(err.Error(), "107") {
		t.Fatalf("err = %v, want it to name the 107-byte limit", err)
	}
	if got := leftovers(t, deep); len(got) != 0 {
		t.Fatalf("refusal left %v behind", got)
	}
	long := filepath.Join(dir, strings.Repeat("x", 120-len(dir)))
	if ln, err := New(socketCfg(long, group), nil).Listen(); err == nil || !strings.Contains(err.Error(), "107") {
		if ln != nil {
			_ = ln.Close()
		}
		t.Fatalf("final path over the limit: err = %v, want the 107-byte limit", err)
	}
}

func TestSocketRemovedOnShutdown(t *testing.T) {
	group, _ := ownGroup(t)
	path := filepath.Join(shortSocketDir(t), "c.sock")
	s := New(socketCfg(path, group), nil)
	ln, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = s.Serve(ln); close(done) }()
	s.Shutdown()
	<-done
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still present after Shutdown: %v", err)
	}
}

func TestSocketShutdownPreservesReplacement(t *testing.T) {
	group, _ := ownGroup(t)
	for _, replacement := range []string{"socket", "file", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			dir := shortSocketDir(t)
			path := filepath.Join(dir, "c.sock")
			s := serveSocket(t, socketCfg(path, group), nil)
			if err := os.Rename(path, filepath.Join(dir, "old.sock")); err != nil {
				t.Fatal(err)
			}
			switch replacement {
			case "socket":
				serveSocket(t, socketCfg(path, group), nil)
			case "file":
				if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("old.sock", path); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				s.Shutdown()
				after, err := os.Lstat(path)
				if err != nil || !os.SameFile(before, after) {
					t.Fatalf("Shutdown changed the replacement: %v", err)
				}
			}
			if replacement == "socket" && gateStatus(t, path, "192.0.2.61") != http.StatusNoContent {
				t.Fatal("replacement stopped serving")
			}
		})
	}
}

func TestSocketListenerCloseRemovesBoundPath(t *testing.T) {
	group, _ := ownGroup(t)
	path := filepath.Join(shortSocketDir(t), "c.sock")
	s := New(socketCfg(path, group), nil)
	t.Cleanup(s.Shutdown)
	ln, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Close left the published socket: %v", err)
	}
}

func TestSocketServeClosesOnTLSFailure(t *testing.T) {
	group, _ := ownGroup(t)
	path := filepath.Join(shortSocketDir(t), "c.sock")
	cfg := socketCfg(path, group)
	cfg.Challenge.TLSCert = filepath.Join(t.TempDir(), "absent.crt")
	cfg.Challenge.TLSKey = filepath.Join(t.TempDir(), "absent.key")
	s := New(cfg, nil)
	ln, err := listenUnixSocket(path, group)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := s.Serve(ln); err == nil {
		t.Fatal("Serve accepted missing TLS material")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Serve left the socket after TLS failure: %v", err)
	}
}

func TestSocketListenerAddrIsPublishedPath(t *testing.T) {
	group, _ := ownGroup(t)
	path := filepath.Join(shortSocketDir(t), "c.sock")
	s := New(socketCfg(path, group), nil)
	t.Cleanup(s.Shutdown)
	ln, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if ln.Addr().Network() != "unix" || ln.Addr().String() != path {
		t.Fatalf("Addr = %v, want unix:%s", ln.Addr(), path)
	}
}

func TestSocketShutdownClosesUnservedListener(t *testing.T) {
	group, _ := ownGroup(t)
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "c.sock")
	s := New(socketCfg(path, group), nil)
	ln, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	// Keep a name for the bound inode after Shutdown removes the published
	// name, so the dial proves the descriptor closed too.
	alias := filepath.Join(dir, "alias.sock")
	if linkErr := os.Link(path, alias); linkErr != nil {
		t.Fatal(linkErr)
	}
	s.Shutdown()
	conn, err := net.DialTimeout("unix", alias, time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatal("Shutdown left an unserved listener accepting connections")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Shutdown left the published socket: %v", err)
	}
}

func TestSocketListenAfterShutdownRefused(t *testing.T) {
	group, _ := ownGroup(t)
	dir := shortSocketDir(t)
	s := New(socketCfg(filepath.Join(dir, "c.sock"), group), nil)
	s.Shutdown()
	ln, err := s.Listen()
	if ln != nil {
		_ = ln.Close()
	}
	if !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Listen after Shutdown = %v, want ErrServerClosed", err)
	}
	if got := leftovers(t, dir); len(got) != 0 {
		t.Fatalf("Listen after Shutdown left %v", got)
	}
}

func TestSocketRefusesActiveListener(t *testing.T) {
	group, _ := ownGroup(t)
	path := filepath.Join(shortSocketDir(t), "c.sock")
	first := serveSocket(t, socketCfg(path, group), nil)
	for _, second := range []*Server{first, New(socketCfg(path, group), nil)} {
		ln, err := second.Listen()
		if ln != nil {
			_ = ln.Close()
		}
		if err == nil {
			t.Fatal("Listen replaced an active socket")
		}
		if code := gateStatus(t, path, "192.0.2.61"); code != http.StatusNoContent {
			t.Fatalf("original listener stopped serving: %d", code)
		}
	}
}

func TestSocketRefusesWritableAncestor(t *testing.T) {
	group, _ := ownGroup(t)
	dir := shortSocketDir(t)
	parent := filepath.Join(dir, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil { // #nosec G302 -- unsafe ancestor fixture
		t.Fatal(err)
	}
	s := New(socketCfg(filepath.Join(parent, "c.sock"), group), nil)
	t.Cleanup(s.Shutdown)
	ln, err := s.Listen()
	if ln != nil {
		_ = ln.Close()
	}
	if err == nil || !strings.Contains(err.Error(), dir) {
		t.Fatalf("Listen with replaceable parent = %v, want refusal naming the ancestor", err)
	}
}

func TestSocketRefusesUncleanPath(t *testing.T) {
	group, _ := ownGroup(t)
	dir := shortSocketDir(t)
	for _, path := range []string{dir + "/../" + filepath.Base(dir) + "/c.sock", dir + "//c.sock", dir + "/c.sock/"} {
		if _, err := CheckSocketPlacement(path, group); err == nil {
			t.Errorf("accepted unclean socket path %q", path)
		}
	}
}

func TestSocketAncestorsThroughSymlink(t *testing.T) {
	group, _ := ownGroup(t)
	dir := shortSocketDir(t)
	shared := filepath.Join(dir, "shared")
	target := filepath.Join(shared, "target")
	parent := filepath.Join(target, "parent")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("shared/target", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "link", "parent", "c.sock")
	for _, tc := range []struct {
		name string
		mode os.FileMode
		ok   bool
	}{
		{"protected", 0o700, true},
		{"sticky", os.ModeSticky | 0o777, true},
		{"replaceable", 0o777, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Chmod(shared, tc.mode); err != nil {
				t.Fatal(err)
			}
			s := New(socketCfg(path, group), nil)
			t.Cleanup(s.Shutdown)
			ln, err := s.Listen()
			if ln != nil {
				_ = ln.Close()
			}
			if tc.ok && err != nil {
				t.Fatal(err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), shared)) {
				t.Fatalf("Listen = %v, want refusal naming the symlink target's ancestor", err)
			}
		})
	}
}

func TestSocketListenShutdownConcurrent(t *testing.T) {
	group, _ := ownGroup(t)
	path := filepath.Join(shortSocketDir(t), "c.sock")
	for range 50 {
		s := New(socketCfg(path, group), nil)
		start := make(chan struct{})
		var ln net.Listener
		var err error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			ln, err = s.Listen()
		}()
		go func() {
			defer wg.Done()
			<-start
			s.Shutdown()
		}()
		close(start)
		wg.Wait()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatal(err)
		}
		if ln != nil {
			_ = ln.(interface{ SetDeadline(time.Time) error }).SetDeadline(time.Now())
			conn, acceptErr := ln.Accept()
			if conn != nil {
				_ = conn.Close()
			}
			_ = ln.Close()
			if !errors.Is(acceptErr, net.ErrClosed) {
				t.Fatalf("Shutdown left listener open: Accept = %v", acceptErr)
			}
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("concurrent Listen/Shutdown left socket: %v", err)
		}
	}
}

func TestSocketModeNeverUsesWebUITLS(t *testing.T) {
	cfg := socketCfg("/run/csm/challenge.sock", "nginx")
	cfg.WebUI.TLSCert = "/etc/csm/webui.crt"
	cfg.WebUI.TLSKey = "/etc/csm/webui.key"
	s, _ := newTestServer(t, cfg)
	if cert, key := s.resolveTLSMaterial(); cert != "" || key != "" {
		t.Fatalf("got (%q, %q), want no TLS on a socket by default", cert, key)
	}
}

func TestNewPortGateSkipsSocketListener(t *testing.T) {
	g, err := NewPortGate(PortGateConfig{ListenAddr: config.ChallengeSocketExample, ListenPort: 8439})
	if err != nil || g != nil {
		t.Fatalf("NewPortGate(socket) = (%v, %v), want (nil, nil)", g, err)
	}
}

// A listed proxy names a shared transport, not a visitor. When the host-local
// guard refuses to trust it, the request must fail, not run as that address:
// a gate answer or cookie for the proxy would cover everyone behind it.
func TestListedPeerIsNeverAVisitor(t *testing.T) {
	gate := func(t *testing.T, trusted []string, peer, xff string) int {
		t.Helper()
		cfg := baseCfg()
		cfg.Challenge.TrustedProxies = trusted
		s := New(cfg, NewIPList(filepath.Join(t.TempDir(), "challenge_ips.txt")))
		req, _ := http.NewRequest(http.MethodGet, "/challenge/gate", nil)
		req.RemoteAddr = peer
		req.Header.Set("X-Forwarded-For", xff)
		rec := httptest.NewRecorder()
		s.srv.Handler.ServeHTTP(rec, req)
		return rec.Code
	}
	t.Run("host-local listed peer", func(t *testing.T) {
		pinHost(t, testHostAddr, "198.51.100.9")
		if code := gate(t, []string{"198.51.100.0/24"}, "198.51.100.9:1234", "192.0.2.50"); code != http.StatusBadRequest {
			t.Fatalf("gate = %d, want 400", code)
		}
	})
	t.Run("host-local listed hop", func(t *testing.T) {
		pinHost(t, testHostAddr, "198.51.100.9")
		if code := gate(t, []string{"198.51.100.0/24"}, "198.51.100.2:1234", "192.0.2.50, 198.51.100.9"); code != http.StatusBadRequest {
			t.Fatalf("gate = %d, want 400", code)
		}
	})
	t.Run("unknown host set", func(t *testing.T) {
		t.Cleanup(netutil.SetHostAddressLookup(func() ([]net.IP, error) { return nil, errors.New("netlink down") }))
		if code := gate(t, []string{"198.51.100.2"}, "198.51.100.2:1234", "192.0.2.50"); code != http.StatusBadRequest {
			t.Fatalf("gate = %d, want 400", code)
		}
	})
	t.Run("control: unlisted host address is its own visitor", func(t *testing.T) {
		if code := gate(t, nil, "127.0.0.1:1234", "192.0.2.50"); code != http.StatusNoContent {
			t.Fatalf("gate = %d, want 204", code)
		}
	})
}
