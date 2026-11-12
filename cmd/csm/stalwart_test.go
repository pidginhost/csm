package main

import (
	"bytes"
	"context"
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
	http     stalwartapi.HTTPSettings
	readErr  error
	writeErr error
	writes   []string
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
	return []string{"store: reloaded with a note"}, nil
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
		loadConfig: func() (*config.Config, error) { return cfg, nil },
		readStatus: func() ([]byte, error) { return status, nil },
		detectMTA:  func() platform.MTAKind { return platform.MTAStalwart },
		webUsers:   func() []string { return []string{"www-data"} },
		getenv:     func(k string) string { return h.env[k] },
		readFile:   os.ReadFile,
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
