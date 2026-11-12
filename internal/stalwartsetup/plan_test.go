package stalwartsetup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/stalwartapi"
)

type fakeAPI struct {
	levels    []stalwartapi.TracingLevel
	http      stalwartapi.HTTPSettings
	bans      stalwartapi.BanPeriods
	listeners []stalwartapi.Listener
	proxy     []string
	readErr   error
	writeErr  error
	failOn    string
	calls     []string
}

func (f *fakeAPI) read(name string) error {
	f.calls = append(f.calls, name)
	return f.readErr
}

func (f *fakeAPI) write(call string) error {
	f.calls = append(f.calls, call)
	if f.failOn != "" && strings.HasPrefix(call, f.failOn) {
		return errors.New("refused")
	}
	return f.writeErr
}

func (f *fakeAPI) TracingLevels(context.Context) ([]stalwartapi.TracingLevel, error) {
	return f.levels, f.read("TracingLevels")
}
func (f *fakeAPI) SetTracingLevel(_ context.Context, id, event, level string) error {
	return f.write(fmt.Sprintf("SetTracingLevel(%s,%s,%s)", id, event, level))
}
func (f *fakeAPI) HTTPSettings(context.Context) (stalwartapi.HTTPSettings, error) {
	return f.http, f.read("HTTPSettings")
}
func (f *fakeAPI) SetHTTPSettings(_ context.Context, h stalwartapi.HTTPSettings) error {
	return f.write(fmt.Sprintf("SetHTTPSettings(%s,%d)", h.ClientIPSource, h.ForwardedHops))
}
func (f *fakeAPI) BanPeriods(context.Context) (stalwartapi.BanPeriods, error) {
	return f.bans, f.read("BanPeriods")
}
func (f *fakeAPI) SetBanPeriods(_ context.Context, d time.Duration) error {
	return f.write(fmt.Sprintf("SetBanPeriods(%s)", d))
}
func (f *fakeAPI) Listeners(context.Context) ([]stalwartapi.Listener, error) {
	return f.listeners, f.read("Listeners")
}
func (f *fakeAPI) ProxyTrustedNetworks(context.Context) ([]string, error) {
	return f.proxy, f.read("ProxyTrustedNetworks")
}
func (f *fakeAPI) ReloadSettings(context.Context) ([]string, error) {
	return []string{"w: reloaded"}, f.write("ReloadSettings")
}

func listener(name, proto string, binds ...string) stalwartapi.Listener {
	l := stalwartapi.Listener{ID: name, Name: name, Protocol: proto}
	for _, b := range binds {
		l.Bind = append(l.Bind, netip.MustParseAddrPort(b))
	}
	return l
}

func fieldListeners() []stalwartapi.Listener {
	return []stalwartapi.Listener{
		listener("smtp", "smtp", "[::]:25"),
		listener("submissions", "smtp", "[::]:465"),
		listener("imaps", "imap", "[::]:993"),
		listener("pop3s", "pop3", "[::]:995"),
		listener("http", "http", "127.0.0.1:8080"),
	}
}

func dur(d time.Duration) *time.Duration { return &d }

func freshAPI() *fakeAPI {
	return &fakeAPI{http: stalwartapi.HTTPSettings{ClientIPSource: "peer", ForwardedHops: 1}, listeners: fieldListeners()}
}

func configuredAPI() *fakeAPI {
	day := dur(24 * time.Hour)
	return &fakeAPI{
		levels:    []stalwartapi.TracingLevel{{ID: "t1", Event: "auth.failed", Level: "info"}},
		http:      stalwartapi.HTTPSettings{ClientIPSource: "xForwardedFor", ForwardedHops: 1},
		bans:      stalwartapi.BanPeriods{Auth: day, Abuse: day, Scan: day},
		listeners: fieldListeners(),
	}
}

func fieldInputs() Inputs {
	return Inputs{BlockExpiry: 24 * time.Hour, LockManaged: true, LockedPorts: []int{8080}, WebUsers: []string{"www-data"}}
}

func inspect(t *testing.T, api *fakeAPI, in Inputs) Plan {
	t.Helper()
	p, err := Inspect(context.Background(), api, in)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	names := make([]string, len(p.Steps))
	for i, s := range p.Steps {
		names[i] = s.Name
	}
	want := []string{"failed-login logging", "webmail client addresses", "ban expiry", "proxy protocol listeners"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("steps = %q, want %q", names, want)
	}
	return p
}

func states(p Plan) []State {
	out := make([]State, len(p.Steps))
	for i, s := range p.Steps {
		out[i] = s.State
	}
	return out
}

func applyCalls(t *testing.T, api *fakeAPI, p Plan) []string {
	t.Helper()
	api.calls = nil
	if _, err := p.Apply(context.Background(), api); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return api.calls
}

func TestPlanFreshStalwart(t *testing.T) {
	api := freshAPI()
	p := inspect(t, api, fieldInputs())
	if got, want := states(p), []State{Change, Change, Change, Done}; !reflect.DeepEqual(got, want) {
		t.Fatalf("states = %v, want %v", got, want)
	}
	api.calls = nil
	warnings, err := p.Apply(context.Background(), api)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"SetTracingLevel(,auth.failed,info)",
		"SetHTTPSettings(xForwardedFor,1)",
		"SetBanPeriods(24h0m0s)",
		"ReloadSettings",
	}
	if !reflect.DeepEqual(api.calls, want) {
		t.Fatalf("calls = %q, want %q", api.calls, want)
	}
	if !reflect.DeepEqual(warnings, []string{"w: reloaded"}) {
		t.Fatalf("warnings = %q", warnings)
	}
}

func TestPlanAlreadyConfiguredAppliesNothing(t *testing.T) {
	api := configuredAPI()
	p := inspect(t, api, fieldInputs())
	if got, want := states(p), []State{Done, Done, Done, Done}; !reflect.DeepEqual(got, want) {
		t.Fatalf("states = %v, want %v (%+v)", got, want, p.Steps)
	}
	if calls := applyCalls(t, api, p); len(calls) != 0 {
		t.Fatalf("Apply made calls %q", calls)
	}
}

func TestPlanSkipsForwardedWhenHTTPListenerPublic(t *testing.T) {
	api := freshAPI()
	api.listeners = append(api.listeners, listener("https", "http", "[::]:443"))
	in := fieldInputs()
	in.LockedPorts = []int{8080, 443}
	p := inspect(t, api, in)
	s := p.Steps[1]
	if s.State != Skipped || !strings.Contains(s.Detail, "https") || !strings.Contains(s.Detail, "[::]:443") {
		t.Fatalf("step 2 = %+v, want Skipped naming https and [::]:443", s)
	}
	for _, c := range applyCalls(t, api, p) {
		if strings.HasPrefix(c, "SetHTTPSettings") {
			t.Fatalf("Apply changed the client address source: %q", c)
		}
	}
}

func TestPlanSkipsForwardedWithoutLock(t *testing.T) {
	for name, in := range map[string]Inputs{
		"daemon not managing the firewall": {BlockExpiry: 24 * time.Hour, LockManaged: false, LockedPorts: []int{8080}, WebUsers: []string{"www-data"}},
		"port not locked":                  {BlockExpiry: 24 * time.Hour, LockManaged: true, WebUsers: []string{"www-data"}},
	} {
		t.Run(name, func(t *testing.T) {
			s := inspect(t, freshAPI(), in).Steps[1]
			if s.State != Skipped || !strings.Contains(s.Detail, `local_port_locks: ["8080:www-data,stalwart"]`) {
				t.Fatalf("step 2 = %+v, want Skipped with the lock line", s)
			}
		})
	}
}

func TestPlanFlagsUnsafeForwarded(t *testing.T) {
	api := freshAPI()
	api.http = stalwartapi.HTTPSettings{ClientIPSource: "xForwardedFor", ForwardedHops: 1}
	in := fieldInputs()
	in.LockedPorts = nil
	p := inspect(t, api, in)
	if p.Steps[1].State != Unsafe {
		t.Fatalf("step 2 = %+v, want Unsafe", p.Steps[1])
	}
	for _, c := range applyCalls(t, api, p) {
		if strings.HasPrefix(c, "SetHTTPSettings") {
			t.Fatalf("Apply touched the client address source: %q", c)
		}
	}
}

func TestPlanTracingLevelVisibility(t *testing.T) {
	api := configuredAPI()
	api.levels = []stalwartapi.TracingLevel{{ID: "t7", Event: "auth.failed", Level: "warn"}}
	if s := inspect(t, api, fieldInputs()).Steps[0]; s.State != Done {
		t.Fatalf("warn override = %+v, want Done", s)
	}
	api.levels = []stalwartapi.TracingLevel{{ID: "t0", Event: "auth.success", Level: "info"}, {ID: "t7", Event: "auth.failed", Level: "debug"}}
	p := inspect(t, api, fieldInputs())
	if p.Steps[0].State != Change {
		t.Fatalf("debug override = %+v, want Change", p.Steps[0])
	}
	if calls := applyCalls(t, api, p); !reflect.DeepEqual(calls, []string{"SetTracingLevel(t7,auth.failed,info)", "ReloadSettings"}) {
		t.Fatalf("calls = %q", calls)
	}
}

func TestPlanBanExpiryFollowsBlockLength(t *testing.T) {
	api := configuredAPI()
	hour := dur(time.Hour)
	api.bans = stalwartapi.BanPeriods{Auth: hour, Abuse: hour, Scan: nil}
	s := inspect(t, api, fieldInputs()).Steps[2]
	if s.State != Change || !strings.Contains(s.Detail, "1h") || !strings.Contains(s.Detail, "permanent") || !strings.Contains(s.Detail, "24h") {
		t.Fatalf("step 3 = %+v, want Change showing 1h, permanent and 24h", s)
	}
}

func TestPlanReportsProxyListeners(t *testing.T) {
	api := configuredAPI()
	api.listeners[0].ProxyNetworks = []string{"192.0.2.0/24"}
	s := inspect(t, api, fieldInputs()).Steps[3]
	if s.State != Warn || !strings.Contains(s.Detail, "smtp") || strings.Contains(s.Detail, "imaps") {
		t.Fatalf("listener override: step 4 = %+v, want Warn naming only smtp", s)
	}

	api = configuredAPI()
	api.proxy = []string{"198.51.100.0/24"}
	s = inspect(t, api, fieldInputs()).Steps[3]
	if s.State != Warn {
		t.Fatalf("global networks: step 4 = %+v, want Warn", s)
	}
	for _, name := range []string{"smtp", "submissions", "imaps", "pop3s"} {
		if !strings.Contains(s.Detail, name) {
			t.Fatalf("global networks: detail %q does not name %s", s.Detail, name)
		}
	}
	if strings.Contains(s.Detail, "http") {
		t.Fatalf("global networks: detail %q names the HTTP listener", s.Detail)
	}
}

func TestPlanStopsOnReadError(t *testing.T) {
	api := freshAPI()
	api.readErr = errors.New("boom")
	p, err := Inspect(context.Background(), api, fieldInputs())
	if !errors.Is(err, api.readErr) || len(p.Steps) != 0 {
		t.Fatalf("Inspect = %+v, %v; want the read error and no plan", p, err)
	}
}

func TestPlanApplyStopsAtFailedWrite(t *testing.T) {
	api := freshAPI()
	p := inspect(t, api, fieldInputs())
	api.calls = nil
	api.writeErr = errors.New("refused")
	_, err := p.Apply(context.Background(), api)
	if !errors.Is(err, api.writeErr) || !strings.Contains(err.Error(), "failed-login logging") {
		t.Fatalf("err = %v, want the write error naming the step", err)
	}
	if len(api.calls) != 1 {
		t.Fatalf("calls after the failure = %q, want the one failed write", api.calls)
	}
}

// Settings written before a failed write are reloaded, so a second run that
// finds them stored does not leave them inactive.
func TestPlanApplyReloadsWhatItWroteBeforeAFailure(t *testing.T) {
	api := freshAPI()
	p := inspect(t, api, fieldInputs())
	api.calls = nil
	api.failOn = "SetHTTPSettings"
	_, err := p.Apply(context.Background(), api)
	if err == nil || !strings.Contains(err.Error(), "webmail client addresses") {
		t.Fatalf("err = %v, want the failed step named", err)
	}
	want := []string{"SetTracingLevel(,auth.failed,info)", "SetHTTPSettings(xForwardedFor,1)", "ReloadSettings"}
	if !reflect.DeepEqual(api.calls, want) {
		t.Fatalf("calls = %q, want %q", api.calls, want)
	}
}
