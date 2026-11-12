package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/control"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/stalwartapi"
	"github.com/pidginhost/csm/internal/stalwartsetup"
)

const setupTestPassword = "s3cret-test"

// setupFakeAPI is a Stalwart with nothing prepared and one loopback HTTP
// listener on 8080.
type setupFakeAPI struct {
	http      stalwartapi.HTTPSettings
	readErr   error
	writeErr  error
	reloadErr error
	writes    []string
}

func (f *setupFakeAPI) TracingLevels(context.Context) ([]stalwartapi.TracingLevel, error) {
	return nil, f.readErr
}
func (f *setupFakeAPI) SetTracingLevel(_ context.Context, id, event, level string) error {
	f.writes = append(f.writes, "tracing")
	return f.writeErr
}
func (f *setupFakeAPI) HTTPSettings(context.Context) (stalwartapi.HTTPSettings, error) {
	return f.http, f.readErr
}
func (f *setupFakeAPI) SetHTTPSettings(context.Context, stalwartapi.HTTPSettings) error {
	f.writes = append(f.writes, "http")
	return f.writeErr
}
func (f *setupFakeAPI) BanPeriods(context.Context) (stalwartapi.BanPeriods, error) {
	return stalwartapi.BanPeriods{}, f.readErr
}
func (f *setupFakeAPI) SetBanPeriods(context.Context, time.Duration) error {
	f.writes = append(f.writes, "bans")
	return f.writeErr
}
func (f *setupFakeAPI) Listeners(context.Context) ([]stalwartapi.Listener, error) {
	return []stalwartapi.Listener{
		{Name: "smtp", Protocol: "smtp", Bind: []netip.AddrPort{netip.MustParseAddrPort("[::]:25")}},
		{Name: "http", Protocol: "http", Bind: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:8080")}},
	}, f.readErr
}
func (f *setupFakeAPI) ProxyTrustedNetworks(context.Context) ([]string, error) { return nil, f.readErr }
func (f *setupFakeAPI) ReloadSettings(context.Context) ([]string, error) {
	f.writes = append(f.writes, "reload")
	return []string{"store: reloaded with a note"}, f.reloadErr
}

type setupHarness struct {
	deps    stalwartSetupDeps
	api     *setupFakeAPI
	env     map[string]string
	gotURL  string
	gotUser string
	gotPass string
}

func setupStatusJSON(t *testing.T, a health.AutomationStatus) []byte {
	t.Helper()
	b, err := json.Marshal(control.StatusResult{Snapshot: &health.Snapshot{Automation: a}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newSetupHarness(t *testing.T) *setupHarness {
	t.Helper()
	h := &setupHarness{
		api: &setupFakeAPI{http: stalwartapi.HTTPSettings{ClientIPSource: "peer", ForwardedHops: 1}},
		env: map[string]string{"STALWART_USER": "admin", "STALWART_PASSWORD": setupTestPassword},
	}
	cfg := &config.Config{}
	cfg.AutoResponse.BlockExpiry = "12h"
	cfg.Stalwart.APIURL = "http://127.0.0.1:8080"
	status := setupStatusJSON(t, health.AutomationStatus{FirewallManaged: true, FirewallLocalPortLocks: []int{8080}})
	h.deps = stalwartSetupDeps{
		loadConfig:    func() (*config.Config, error) { return cfg, nil },
		readStatus:    func() ([]byte, error) { return status, nil },
		detectMTA:     func() platform.MTAKind { return platform.MTAStalwart },
		webUsers:      func() []string { return []string{"www-data"} },
		getenv:        func(k string) string { return h.env[k] },
		readFile:      os.ReadFile,
		checkListener: func(string) error { return nil },
		newAPI: func(url, user, password string) stalwartsetup.API {
			h.gotURL, h.gotUser, h.gotPass = url, user, password
			return h.api
		},
	}
	return h
}

func (h *setupHarness) run(args ...string) (int, string) {
	var out bytes.Buffer
	code := runStalwartSetup(args, h.deps, &out)
	return code, out.String()
}

func TestStalwartSetupRefusesNonStalwartHost(t *testing.T) {
	h := newSetupHarness(t)
	h.deps.detectMTA = func() platform.MTAKind { return platform.MTAPostfix }
	code, out := h.run()
	if code != 2 || !strings.Contains(out, "postfix") {
		t.Fatalf("code %d, out %q; want 2 naming postfix", code, out)
	}
	if h.gotUser != "" {
		t.Fatal("the API was contacted on a non-Stalwart host")
	}
}

func TestStalwartSetupNeedsLogin(t *testing.T) {
	h := newSetupHarness(t)
	h.env = map[string]string{}
	code, out := h.run()
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	for _, want := range []string{"STALWART_USER", "STALWART_PASSWORD", "--password-file"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q does not name %s", out, want)
		}
	}
}

func TestStalwartSetupNeverPrintsPassword(t *testing.T) {
	file := t.TempDir() + "/pw"
	if err := os.WriteFile(file, []byte(setupTestPassword+"\r\nsecond line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*setupHarness){
		"success":      func(*setupHarness) {},
		"unauthorized": func(h *setupHarness) { h.api.readErr = fmt.Errorf("stalwart /jmap/: %w", stalwartapi.ErrUnauthorized) },
		"transport": func(h *setupHarness) {
			h.api.readErr = errors.New("dial tcp: refused while sending " + setupTestPassword)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newSetupHarness(t)
			h.env = map[string]string{"STALWART_USER": "admin"}
			mutate(h)
			_, out := h.run("--password-file", file)
			if h.gotPass != setupTestPassword {
				t.Fatalf("API password = %q, want the first line without CR/LF", h.gotPass)
			}
			if strings.Contains(out, setupTestPassword) {
				t.Fatalf("output contains the password: %q", out)
			}
		})
	}
}

func TestStalwartSetupDryRunWritesNothing(t *testing.T) {
	h := newSetupHarness(t)
	code, out := h.run("--dry-run")
	if code != 0 {
		t.Fatalf("code = %d, out %q", code, out)
	}
	if len(h.api.writes) != 0 {
		t.Fatalf("dry run wrote %q", h.api.writes)
	}
	for _, want := range []string{
		"failed-login logging: change: ",
		"webmail client addresses: change: ",
		"ban expiry: change: ",
		"proxy protocol listeners: done: ",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q lacks %q", out, want)
		}
	}
	if h.gotURL != "http://127.0.0.1:8080" || h.gotUser != "admin" {
		t.Fatalf("API %q as %q", h.gotURL, h.gotUser)
	}
}

func TestStalwartSetupAppliesAndReloadsOnce(t *testing.T) {
	h := newSetupHarness(t)
	code, out := h.run("--url", "http://127.0.0.1:18080")
	if code != 0 {
		t.Fatalf("code = %d, out %q", code, out)
	}
	if want := []string{"tracing", "http", "bans", "reload"}; !reflect.DeepEqual(h.api.writes, want) {
		t.Fatalf("writes = %q, want %q", h.api.writes, want)
	}
	if h.gotURL != "http://127.0.0.1:18080" {
		t.Fatalf("--url ignored: %q", h.gotURL)
	}
	for _, want := range []string{"failed-login logging: changed: ", "ban expiry: changed: ", "12h", "store: reloaded with a note"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q lacks %q", out, want)
		}
	}
}

func TestStalwartSetupLockNeedsRunningDaemon(t *testing.T) {
	for name, status := range map[string]func(t *testing.T) ([]byte, error){
		"daemon down": func(*testing.T) ([]byte, error) { return nil, errors.New("connection refused") },
		"firewall not managed": func(t *testing.T) ([]byte, error) {
			return setupStatusJSON(t, health.AutomationStatus{FirewallLocalPortLocks: []int{8080}}), nil
		},
		"port not locked": func(t *testing.T) ([]byte, error) {
			return setupStatusJSON(t, health.AutomationStatus{FirewallManaged: true, FirewallLocalPortLocks: []int{9000}}), nil
		},
		"no snapshot": func(*testing.T) ([]byte, error) { return []byte(`{"version":"x"}`), nil },
	} {
		t.Run(name, func(t *testing.T) {
			h := newSetupHarness(t)
			b, err := status(t)
			h.deps.readStatus = func() ([]byte, error) { return b, err }
			code, out := h.run("--dry-run")
			if code != 0 || !strings.Contains(out, "webmail client addresses: skipped: ") {
				t.Fatalf("code %d, out %q; want step 2 skipped", code, out)
			}
			if !strings.Contains(out, `local_port_locks: ["8080:www-data,stalwart"]`) {
				t.Fatalf("output %q lacks the lock line", out)
			}
		})
	}
}

func TestStalwartSetupExitCodes(t *testing.T) {
	h := newSetupHarness(t)
	h.api.http = stalwartapi.HTTPSettings{ClientIPSource: "xForwardedFor", ForwardedHops: 1}
	h.deps.readStatus = func() ([]byte, error) { return nil, errors.New("down") }
	if code, out := h.run("--dry-run"); code != 1 || !strings.Contains(out, "unsafe") {
		t.Fatalf("unsafe: code %d, out %q; want 1", code, out)
	}

	h = newSetupHarness(t)
	h.api.writeErr = errors.New("refused")
	if code, out := h.run(); code != 1 || !strings.Contains(out, "refused") {
		t.Fatalf("write error: code %d, out %q; want 1", code, out)
	}

	h = newSetupHarness(t)
	h.deps.readStatus = func() ([]byte, error) { return nil, errors.New("down") }
	if code, out := h.run(); code != 0 {
		t.Fatalf("skipped step: code %d, out %q; want 0", code, out)
	}

	h = newSetupHarness(t)
	h.api.readErr = fmt.Errorf("stalwart /jmap/: %w", stalwartapi.ErrUnauthorized)
	if code, _ := h.run(); code != 2 {
		t.Fatalf("refused login: code %d, want 2", code)
	}

	h = newSetupHarness(t)
	if code, _ := h.run("extra"); code != 2 {
		t.Fatalf("stray argument: code %d, want 2", code)
	}
}

func TestStalwartSetupRedactsPlanAndLogin(t *testing.T) {
	for _, mode := range []string{"dry", "apply", "login"} {
		t.Run(mode, func(t *testing.T) {
			h := newSetupHarness(t)
			h.api.http.ClientIPSource = setupTestPassword
			if mode == "login" {
				h.env["STALWART_USER"] = setupTestPassword
				h.api.readErr = stalwartapi.ErrUnauthorized
			}
			args := []string{}
			if mode == "dry" {
				args = append(args, "--dry-run")
			}
			_, out := h.run(args...)
			if strings.Contains(out, setupTestPassword) {
				t.Fatal("password exposed by output")
			}
		})
	}
}

func TestStalwartSetupRejectsUnsafeURLOverride(t *testing.T) {
	h := newSetupHarness(t)
	code, _ := h.run("--url", "http://192.0.2.1:8080")
	if code != 2 || h.gotURL != "" {
		t.Fatal("unsafe override reached API")
	}
}

func TestStalwartSetupRemoteCannotUseLocalLocks(t *testing.T) {
	h := newSetupHarness(t)
	code, out := h.run("--url", "https://mail.example.org", "--dry-run")
	if code != 0 || !strings.Contains(out, "webmail client addresses: skipped:") {
		t.Fatal("remote listener trusted local firewall")
	}
}

func TestStalwartSetupReloadFailureSaysRestart(t *testing.T) {
	h := newSetupHarness(t)
	h.api.reloadErr = errors.New("timeout")
	code, out := h.run()
	if code != 1 || !strings.Contains(out, "restart Stalwart") {
		t.Fatalf("code %d, out %q; want 1 telling the operator to restart Stalwart", code, out)
	}
}

func TestStalwartSetupRefusesForeignListener(t *testing.T) {
	h := newSetupHarness(t)
	h.deps.checkListener = func(string) error { return errors.New("port 8080 is held by uid 1001") }
	code, out := h.run()
	if code != 2 || h.gotUser != "" || !strings.Contains(out, "uid 1001") {
		t.Fatalf("code %d, out %q, api contacted %v; want 2 before any login is sent", code, out, h.gotUser != "")
	}
}

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
