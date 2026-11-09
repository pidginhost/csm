package challenge

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
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
