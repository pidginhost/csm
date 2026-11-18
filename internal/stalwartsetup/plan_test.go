package stalwartsetup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/ipmap"
	"github.com/pidginhost/csm/internal/stalwartapi"
)

type fakeAPI struct {
	levels     []stalwartapi.TracingLevel
	http       stalwartapi.HTTPSettings
	bans       stalwartapi.BanPeriods
	listeners  []stalwartapi.Listener
	proxy      []string
	spam       stalwartapi.SpamSettings
	stageOff   bool
	readErr    error
	readErrors map[string]error
	writeErr   error
	failOn     string
	reloadErr  error
	calls      []string

	rules map[string]stalwartapi.SpamRule
	tags  map[string]stalwartapi.SpamTag

	roles     []stalwartapi.Role
	domains   []stalwartapi.Domain
	accounts  []stalwartapi.Account
	acctRoles map[string][]string
	keys      map[string][]stalwartapi.APIKey
	keyIPs    map[string][]string
	creds     map[string][]string
	nextID    int
}

func (f *fakeAPI) read(name string) error {
	f.calls = append(f.calls, name)
	if err := f.readErrors[name]; err != nil {
		return err
	}
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
	if err := f.write(fmt.Sprintf("SetTracingLevel(%s,%s,%s)", id, event, level)); err != nil {
		return err
	}
	for i := range f.levels {
		if f.levels[i].ID == id {
			f.levels[i].Level = level
			return nil
		}
	}
	f.levels = append(f.levels, stalwartapi.TracingLevel{ID: fmt.Sprint(len(f.levels) + 1), Event: event, Level: level})
	return nil
}
func (f *fakeAPI) HTTPSettings(context.Context) (stalwartapi.HTTPSettings, error) {
	return f.http, f.read("HTTPSettings")
}
func (f *fakeAPI) SetHTTPSettings(_ context.Context, h stalwartapi.HTTPSettings) error {
	if err := f.write(fmt.Sprintf("SetHTTPSettings(%s,%d)", h.ClientIPSource, h.ForwardedHops)); err != nil {
		return err
	}
	f.http = h
	return nil
}
func (f *fakeAPI) BanPeriods(context.Context) (stalwartapi.BanPeriods, error) {
	return f.bans, f.read("BanPeriods")
}
func (f *fakeAPI) SetBanPeriods(_ context.Context, d time.Duration) error {
	if err := f.write(fmt.Sprintf("SetBanPeriods(%s)", d)); err != nil {
		return err
	}
	f.bans = stalwartapi.BanPeriods{Auth: dur(d), Abuse: dur(d), Scan: dur(d)}
	return nil
}
func (f *fakeAPI) Listeners(context.Context) ([]stalwartapi.Listener, error) {
	return f.listeners, f.read("Listeners")
}
func (f *fakeAPI) ProxyTrustedNetworks(context.Context) ([]string, error) {
	return f.proxy, f.read("ProxyTrustedNetworks")
}
func (f *fakeAPI) SpamSettings(context.Context) (stalwartapi.SpamSettings, error) {
	return f.spam, f.read("SpamSettings")
}
func (f *fakeAPI) SpamFilterStageOff(context.Context) (bool, error) {
	return f.stageOff, f.read("SpamFilterStageOff")
}
func (f *fakeAPI) ReloadSettings(context.Context) ([]string, error) {
	if err := f.write("ReloadSettings"); err != nil {
		return nil, err
	}
	return []string{"w: reloaded"}, f.reloadErr
}

func (f *fakeAPI) SpamRule(_ context.Context, name string) (stalwartapi.SpamRule, bool, error) {
	if err := f.read("SpamRule"); err != nil {
		return stalwartapi.SpamRule{}, false, err
	}
	r, ok := f.rules[name]
	return r, ok, nil
}
func (f *fakeAPI) CreateSpamRule(_ context.Context, name string, r stalwartapi.SpamRule) error {
	if err := f.write("CreateSpamRule(" + name + ")"); err != nil {
		return err
	}
	if f.rules == nil {
		f.rules = map[string]stalwartapi.SpamRule{}
	}
	f.rules[name] = stalwartapi.SpamRule{ID: "rule-" + name, Type: "Any", Enabled: true, Arms: r.Arms, Else: r.Else}
	return nil
}
func (f *fakeAPI) SetSpamRuleCondition(_ context.Context, id string, arms []stalwartapi.RuleArm, elseExpr string) error {
	if err := f.write("SetSpamRuleCondition(" + id + ")"); err != nil {
		return err
	}
	for name, r := range f.rules {
		if r.ID == id {
			r.Arms, r.Else = arms, elseExpr
			f.rules[name] = r
		}
	}
	return nil
}
func (f *fakeAPI) SpamTag(_ context.Context, tag string) (stalwartapi.SpamTag, bool, error) {
	if err := f.read("SpamTag"); err != nil {
		return stalwartapi.SpamTag{}, false, err
	}
	t, ok := f.tags[tag]
	return t, ok, nil
}
func (f *fakeAPI) CreateSpamTag(_ context.Context, tag string, score float64) error {
	if err := f.write(fmt.Sprintf("CreateSpamTag(%s,%v)", tag, score)); err != nil {
		return err
	}
	if f.tags == nil {
		f.tags = map[string]stalwartapi.SpamTag{}
	}
	f.tags[tag] = stalwartapi.SpamTag{ID: "tag-" + tag, Type: "Score", Tag: tag, Score: score}
	return nil
}

// addressList gives f CSM's rule, switched on, and its tags at CSM's scores.
func addressList(f *fakeAPI) {
	f.rules = map[string]stalwartapi.SpamRule{AddressListRule: {ID: "rule1", Type: "Any", Enabled: true, Arms: AddressListArms(), Else: "false"}}
	f.tags = map[string]stalwartapi.SpamTag{}
	for i, s := range ipmap.Symbols() {
		f.tags[s.Name] = stalwartapi.SpamTag{ID: fmt.Sprint("tag", i), Type: "Score", Tag: s.Name, Score: float64(s.Tenths()) / 10}
	}
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

// stockSpam is a fresh install's spam filter: on, Junk at 5, nothing else.
var stockSpam = stalwartapi.SpamSettings{Enabled: true, ScoreSpam: 5}

func freshAPI() *fakeAPI {
	return &fakeAPI{http: stalwartapi.HTTPSettings{ClientIPSource: "peer", ForwardedHops: 1}, listeners: fieldListeners(), spam: stockSpam}
}

func configuredAPI() *fakeAPI {
	day := dur(24 * time.Hour)
	f := &fakeAPI{
		levels:    []stalwartapi.TracingLevel{{ID: "t1", Event: "auth.failed", Level: "info"}, {ID: "t2", Event: "spam.classify", Level: "info"}},
		http:      stalwartapi.HTTPSettings{ClientIPSource: "xForwardedFor", ForwardedHops: 1},
		bans:      stalwartapi.BanPeriods{Auth: day, Abuse: day, Scan: day},
		listeners: fieldListeners(),
		spam:      stockSpam,
	}
	addressList(f)
	return f
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
	want := []string{"failed-login logging", "webmail client addresses", "ban expiry", "proxy protocol listeners", "spam verdict logging", "spam filter",
		"address list", "response role", "response account", "response key"}
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
	if got, want := states(p), []State{Change, Change, Change, Done, Change, Done, Change, Skipped, Skipped, Skipped}; !reflect.DeepEqual(got, want) {
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
		"SetTracingLevel(,spam.classify,info)",
	}
	want = append(append(want, addressListWrites...), "ReloadSettings")
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
	if got, want := states(p), []State{Done, Done, Done, Done, Done, Done, Done, Skipped, Skipped, Skipped}; !reflect.DeepEqual(got, want) {
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
	spamDone := stalwartapi.TracingLevel{ID: "t2", Event: "spam.classify", Level: "info"}
	api.levels = []stalwartapi.TracingLevel{{ID: "t7", Event: "auth.failed", Level: "warn"}, spamDone}
	if s := inspect(t, api, fieldInputs()).Steps[0]; s.State != Done {
		t.Fatalf("warn override = %+v, want Done", s)
	}
	api.levels = []stalwartapi.TracingLevel{{ID: "t0", Event: "auth.success", Level: "info"}, {ID: "t7", Event: "auth.failed", Level: "debug"}, spamDone}
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
	if !errors.Is(err, api.writeErr) || !errors.Is(err, ErrSettingsWrite) || !strings.Contains(err.Error(), "failed-login logging") {
		t.Fatalf("err = %v, want the settings write error naming the step", err)
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

// Behind the lock, only X-Forwarded-For with one hop is safe: with more hops,
// or the Forwarded header the web server does not set, the client supplies
// the address Stalwart reads.
func TestPlanRewritesSpoofableForwardedSettings(t *testing.T) {
	for _, h := range []stalwartapi.HTTPSettings{
		{ClientIPSource: "xForwardedFor", ForwardedHops: 2},
		{ClientIPSource: "forwarded", ForwardedHops: 1},
	} {
		api := configuredAPI()
		api.http = h
		p := inspect(t, api, fieldInputs())
		if p.Steps[1].State != Change {
			t.Fatalf("%+v: step 2 = %+v, want Change", h, p.Steps[1])
		}
		if calls := applyCalls(t, api, p); !reflect.DeepEqual(calls, []string{"SetHTTPSettings(xForwardedFor,1)", "ReloadSettings"}) {
			t.Fatalf("%+v: calls = %q", h, calls)
		}
	}
}

func TestPlanApplySamePlanTwice(t *testing.T) {
	api := freshAPI()
	p := inspect(t, api, fieldInputs())
	applyCalls(t, api, p)
	if calls := applyCalls(t, api, p); len(calls) != 0 {
		t.Fatalf("second apply made calls: %v", calls)
	}
}

func TestPlanRejectsUnknownHTTPBind(t *testing.T) {
	api := freshAPI()
	api.listeners = append(api.listeners, listener("unknown", "http"))
	p := inspect(t, api, fieldInputs())
	if p.Steps[1].State != Skipped {
		t.Fatal("enabled forwarded addresses without all HTTP binds")
	}
}

func TestPlanRetriesReloadWithoutRewriting(t *testing.T) {
	api := freshAPI()
	p := inspect(t, api, fieldInputs())
	api.failOn = "ReloadSettings"
	if _, err := p.Apply(context.Background(), api); err == nil {
		t.Fatal("expected reload failure")
	}
	api.failOn = ""
	api.calls = nil
	if _, err := p.Apply(context.Background(), api); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(api.calls, []string{"ReloadSettings"}) {
		t.Fatalf("retry calls = %v", api.calls)
	}
	api.calls = nil
	if _, err := p.Apply(context.Background(), api); err != nil || len(api.calls) != 0 {
		t.Fatal("completed plan was not idle")
	}
}

func TestPlanOnlyUnknownHTTPBindIsNotDone(t *testing.T) {
	api := freshAPI()
	api.listeners = []stalwartapi.Listener{listener("unknown", "http")}
	p := inspect(t, api, fieldInputs())
	if p.Steps[1].State != Skipped {
		t.Fatal("unknown HTTP binding reported done")
	}
}

// Trusting one hop is only sound when the web server sets the header
// itself; the step says so.
func TestPlanForwardedStepNamesWebServerHeader(t *testing.T) {
	s := inspect(t, freshAPI(), fieldInputs()).Steps[1]
	if s.State != Change || !strings.Contains(s.Detail, "proxy_set_header X-Forwarded-For") {
		t.Fatalf("step 2 = %+v, want the web server requirement", s)
	}
}

func TestPlanReloadFailureIsMarked(t *testing.T) {
	api := freshAPI()
	p := inspect(t, api, fieldInputs())
	api.reloadErr = errors.New("timeout")
	_, err := p.Apply(context.Background(), api)
	if !errors.Is(err, ErrNotReloaded) {
		t.Fatalf("err = %v, want ErrNotReloaded", err)
	}
}

func stepNamed(t *testing.T, p Plan, name string) Step {
	t.Helper()
	for _, s := range p.Steps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no %q step in %+v", name, p.Steps)
	return Step{}
}

func TestPlanSpamVerdictLoggingChange(t *testing.T) {
	api := freshAPI()
	p := inspect(t, api, fieldInputs())
	s := stepNamed(t, p, "spam verdict logging")
	if s.State != Change || !strings.Contains(s.Detail, "rejected and discarded spam is not logged") {
		t.Fatalf("step = %+v, want Change saying rejected and discarded spam is not logged", s)
	}
	calls := applyCalls(t, api, p)
	if !slices.Contains(calls, "SetTracingLevel(,spam.classify,info)") {
		t.Fatalf("calls = %q, want the spam.classify level set", calls)
	}
	if slices.Index(calls, "ReloadSettings") != len(calls)-1 || slices.Index(calls[:len(calls)-1], "ReloadSettings") >= 0 {
		t.Fatalf("calls = %q, want exactly one ReloadSettings, after every write", calls)
	}
}

func TestPlanSpamVerdictLoggingUpdatesOverride(t *testing.T) {
	api := configuredAPI()
	api.levels = []stalwartapi.TracingLevel{{ID: "t1", Event: "auth.failed", Level: "info"}, {ID: "t9", Event: "spam.classify", Level: "debug"}}
	p := inspect(t, api, fieldInputs())
	if calls := applyCalls(t, api, p); !reflect.DeepEqual(calls, []string{"SetTracingLevel(t9,spam.classify,info)", "ReloadSettings"}) {
		t.Fatalf("calls = %q", calls)
	}
}

func TestPlanSpamVerdictLoggingDone(t *testing.T) {
	for _, level := range []string{"info", "warn", "error"} {
		api := freshAPI()
		api.levels = []stalwartapi.TracingLevel{{ID: "t9", Event: "spam.classify", Level: level}}
		p := inspect(t, api, fieldInputs())
		if s := stepNamed(t, p, "spam verdict logging"); s.State != Done {
			t.Fatalf("%s: step = %+v, want Done", level, s)
		}
		for _, c := range applyCalls(t, api, p) {
			if strings.Contains(c, "spam.classify") {
				t.Fatalf("%s: Apply made %q", level, c)
			}
		}
	}
}

func TestPlanSpamFilterStates(t *testing.T) {
	s := stepNamed(t, inspect(t, freshAPI(), fieldInputs()), "spam filter")
	for _, want := range []string{"files spam to Junk at 5", "never rejects", "never discards"} {
		if s.State != Done || !strings.Contains(s.Detail, want) {
			t.Fatalf("stock: step = %+v, want Done with %q", s, want)
		}
	}

	api := freshAPI()
	api.spam = stalwartapi.SpamSettings{Enabled: true, ScoreSpam: 5, ScoreReject: 12, ScoreDiscard: 20}
	s = stepNamed(t, inspect(t, api, fieldInputs()), "spam filter")
	for _, want := range []string{"files spam to Junk at 5,", "rejects at 12", "discards at 20"} {
		if s.State != Done || !strings.Contains(s.Detail, want) {
			t.Fatalf("scores: step = %+v, want Done with %q", s, want)
		}
	}

	off := "Stalwart's spam filter is off, so inbound mail is not filtered; switch it on in Stalwart's admin interface"
	api = freshAPI()
	api.spam.Enabled = false
	if s := stepNamed(t, inspect(t, api, fieldInputs()), "spam filter"); s.State != Warn || s.Detail != off {
		t.Fatalf("switched off: step = %+v, want Warn", s)
	}
	api = freshAPI()
	api.stageOff = true
	if s := stepNamed(t, inspect(t, api, fieldInputs()), "spam filter"); s.State != Warn || s.Detail != off {
		t.Fatalf("stage off: step = %+v, want Warn", s)
	}
}

// Reporting the filter's switch and action scores must not change those settings.
func TestPlanSpamFilterNeverWrites(t *testing.T) {
	for name, mutate := range map[string]func(*fakeAPI){
		"stock":        func(*fakeAPI) {},
		"switched off": func(f *fakeAPI) { f.spam.Enabled = false },
		"stage off":    func(f *fakeAPI) { f.stageOff = true },
	} {
		t.Run(name, func(t *testing.T) {
			api := configuredAPI()
			mutate(api)
			p := inspect(t, api, fieldInputs())
			if calls := applyCalls(t, api, p); len(calls) != 0 {
				t.Fatalf("Apply made calls %q", calls)
			}
		})
	}
}

func TestPlanSpamReadFailureWarnsAndAllowsSetup(t *testing.T) {
	for _, method := range []string{"SpamSettings", "SpamFilterStageOff"} {
		t.Run(method, func(t *testing.T) {
			api := freshAPI()
			api.readErrors = map[string]error{method: errors.New("private API error detail")}
			p := inspect(t, api, fieldInputs())
			s := stepNamed(t, p, "spam filter")
			if s.State != Warn || s.Detail != "Cannot read Stalwart's spam filter status; check it in Stalwart's admin interface" || s.apply != nil {
				t.Fatal("spam read failure must produce a static, read-only warning")
			}
			want := []string{
				"SetTracingLevel(,auth.failed,info)",
				"SetHTTPSettings(xForwardedFor,1)",
				"SetBanPeriods(24h0m0s)",
				"SetTracingLevel(,spam.classify,info)",
			}
			want = append(append(want, addressListWrites...), "ReloadSettings")
			if calls := applyCalls(t, api, p); !reflect.DeepEqual(calls, want) {
				t.Fatalf("writes = %q, want %q", calls, want)
			}
			p = inspect(t, api, fieldInputs())
			if calls := applyCalls(t, api, p); len(calls) != 0 {
				t.Fatalf("second setup made calls: %q", calls)
			}
		})
	}
}

func TestPlanSpamReadUnauthorizedStopsSetup(t *testing.T) {
	for _, method := range []string{"SpamSettings", "SpamFilterStageOff"} {
		t.Run(method, func(t *testing.T) {
			api := freshAPI()
			api.readErrors = map[string]error{method: fmt.Errorf("login: %w", stalwartapi.ErrUnauthorized)}
			if method == "SpamFilterStageOff" {
				api.readErrors["SpamSettings"] = errors.New("unavailable")
			}
			p, err := Inspect(context.Background(), api, fieldInputs())
			if !errors.Is(err, stalwartapi.ErrUnauthorized) || len(p.Steps) != 0 {
				t.Fatal("unauthorized spam read must return the login error and no plan")
			}
		})
	}
}

func TestPlanSecondSetupWritesNothing(t *testing.T) {
	api := freshAPI()
	p := inspect(t, api, fieldInputs())
	if calls := applyCalls(t, api, p); len(calls) != 4+len(addressListWrites)+1 {
		t.Fatalf("first setup calls = %q, want four writes, the address list and a reload", calls)
	}
	p = inspect(t, api, fieldInputs())
	if got, want := states(p), []State{Done, Done, Done, Done, Done, Done, Done, Skipped, Skipped, Skipped}; !reflect.DeepEqual(got, want) {
		t.Fatalf("second setup states = %v, want %v", got, want)
	}
	if calls := applyCalls(t, api, p); len(calls) != 0 {
		t.Fatalf("second setup made calls: %q", calls)
	}
}

func (f *fakeAPI) id() string {
	f.nextID++
	return fmt.Sprintf("id%d", f.nextID)
}
func (f *fakeAPI) RoleByDescription(_ context.Context, description string) (stalwartapi.Role, bool, error) {
	if err := f.read("RoleByDescription"); err != nil {
		return stalwartapi.Role{}, false, err
	}
	for _, r := range f.roles {
		if r.Description == description {
			return r, true, nil
		}
	}
	return stalwartapi.Role{}, false, nil
}
func (f *fakeAPI) SaveRole(_ context.Context, r stalwartapi.Role) (string, error) {
	if err := f.write(fmt.Sprintf("SaveRole(%s,%s)", r.ID, r.Description)); err != nil {
		return "", err
	}
	for i := range f.roles {
		if f.roles[i].ID == r.ID {
			f.roles[i] = r
			return r.ID, nil
		}
	}
	r.ID = f.id()
	f.roles = append(f.roles, r)
	return r.ID, nil
}
func (f *fakeAPI) Domains(context.Context) ([]stalwartapi.Domain, error) {
	return f.domains, f.read("Domains")
}
func (f *fakeAPI) AccountsNamed(_ context.Context, name string) ([]stalwartapi.Account, error) {
	var out []stalwartapi.Account
	for _, a := range f.accounts {
		if a.Name == name {
			out = append(out, a)
		}
	}
	return out, f.read("AccountsNamed")
}
func (f *fakeAPI) AccountRoleIDs(_ context.Context, id string) ([]string, error) {
	return f.acctRoles[id], f.read("AccountRoleIDs")
}
func (f *fakeAPI) AccountCredentialTypes(_ context.Context, id string) ([]string, error) {
	return f.creds[id], f.read("AccountCredentialTypes")
}
func (f *fakeAPI) CreateAccount(_ context.Context, name, domainID, roleID string) (string, error) {
	if err := f.write(fmt.Sprintf("CreateAccount(%s,%s,%s)", name, domainID, roleID)); err != nil {
		return "", err
	}
	id := f.id()
	email := name
	for _, d := range f.domains {
		if d.ID == domainID {
			email += "@" + d.Name
		}
	}
	f.accounts = append(f.accounts, stalwartapi.Account{ID: id, Name: name, Email: email})
	f.acctRoles[id] = []string{roleID}
	return id, nil
}
func (f *fakeAPI) SetAccountRole(_ context.Context, id, roleID string) error {
	if err := f.write(fmt.Sprintf("SetAccountRole(%s,%s)", id, roleID)); err != nil {
		return err
	}
	f.acctRoles[id] = []string{roleID}
	return nil
}
func (f *fakeAPI) APIKeys(_ context.Context, accountID string) ([]stalwartapi.APIKey, error) {
	return f.keys[accountID], f.read("APIKeys")
}
func (f *fakeAPI) CreateAPIKey(_ context.Context, accountID, description string, allowedIPs []string) (string, string, error) {
	if err := f.write(fmt.Sprintf("CreateAPIKey(%s,%s,%s)", accountID, description, strings.Join(allowedIPs, " "))); err != nil {
		return "", "", err
	}
	id := f.id()
	f.keys[accountID] = append(f.keys[accountID], stalwartapi.APIKey{ID: id, Description: description})
	f.keyIPs[id] = allowedIPs
	return id, "test-key-1", nil
}
func (f *fakeAPI) DeleteAPIKeys(_ context.Context, accountID string, ids []string) error {
	if err := f.write(fmt.Sprintf("DeleteAPIKeys(%s,%s)", accountID, strings.Join(ids, ","))); err != nil {
		return err
	}
	f.keys[accountID] = slices.DeleteFunc(f.keys[accountID], func(k stalwartapi.APIKey) bool { return slices.Contains(ids, k.ID) })
	return nil
}

// responseAPI is a configured Stalwart with its stock User role, one domain
// and nothing of CSM's.
func responseAPI() *fakeAPI {
	api := configuredAPI()
	api.roles = []stalwartapi.Role{{ID: "u", Description: "User"}}
	api.domains = []stalwartapi.Domain{{ID: "d1", Name: "example.org"}}
	api.acctRoles = map[string][]string{}
	api.keys = map[string][]stalwartapi.APIKey{}
	api.keyIPs = map[string][]string{}
	return api
}

// preparedAPI also holds CSM's role and account a1 with its one key.
func preparedAPI() *fakeAPI {
	api := responseAPI()
	api.roles = append(api.roles, stalwartapi.Role{ID: "r1", Description: ResponseRole, Enabled: slices.Clone(ResponsePermissions), RoleIDs: []string{"u"}})
	api.accounts = []stalwartapi.Account{{ID: "a1", Name: ResponseAccount, Email: "csm-response@example.org"}}
	api.acctRoles["a1"] = []string{"r1"}
	api.keys["a1"] = []stalwartapi.APIKey{{ID: "old1", Description: "CSM"}}
	return api
}

// twoKeyAPI is preparedAPI with a second key on a1.
func twoKeyAPI() *fakeAPI {
	api := preparedAPI()
	api.keys["a1"] = append(api.keys["a1"], stalwartapi.APIKey{ID: "old2", Description: "CSM"})
	return api
}

// responseInputs records each key written in api's calls.
func responseInputs(api *fakeAPI, keyAccount string, writeErr error) Inputs {
	in := fieldInputs()
	in.LocalAPI = true
	in.KeyAccount = keyAccount
	in.WriteKey = func(secret string) error {
		api.calls = append(api.calls, "WriteKey("+secret+")")
		return writeErr
	}
	return in
}

func responseStates(p Plan) []State { return states(p)[7:] }

func TestPlanCreatesRoleAccountAndKey(t *testing.T) {
	api := responseAPI()
	p := inspect(t, api, responseInputs(api, "", nil))
	if got, want := states(p), []State{Done, Done, Done, Done, Done, Done, Done, Change, Change, Change}; !reflect.DeepEqual(got, want) {
		t.Fatalf("states = %v, want %v (%+v)", got, want, p.Steps[7:])
	}
	calls := applyCalls(t, api, p)
	want := []string{
		"SaveRole(," + ResponseRole + ")",
		"CreateAccount(csm-response,d1,id1)",
		"CreateAPIKey(id2,CSM,127.0.0.1 ::1)",
		"WriteKey(test-key-1)",
		"APIKeys",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %q, want %q", calls, want)
	}
	role := api.roles[1]
	if role.ID != "id1" || !reflect.DeepEqual(role.Enabled, ResponsePermissions) || !reflect.DeepEqual(role.RoleIDs, []string{"u"}) {
		t.Fatalf("role = %+v, want every response permission and the User role", role)
	}
	if len(api.accounts) != 1 || api.accounts[0].Name != ResponseAccount || !reflect.DeepEqual(api.acctRoles["id2"], []string{"id1"}) {
		t.Fatalf("accounts = %+v, roles %v; want one csm-response holding the response role", api.accounts, api.acctRoles)
	}
	if len(api.keys["id2"]) != 1 || !reflect.DeepEqual(api.keyIPs["id3"], []string{"127.0.0.1", "::1"}) {
		t.Fatalf("keys = %+v, addresses %v; want one loopback-only key", api.keys, api.keyIPs)
	}
}

func TestPlanKeepsWorkingKey(t *testing.T) {
	api := preparedAPI()
	p := inspect(t, api, responseInputs(api, "a1", nil))
	if got, want := responseStates(p), []State{Done, Done, Done}; !reflect.DeepEqual(got, want) {
		t.Fatalf("states = %v, want %v (%+v)", got, want, p.Steps[7:])
	}
	if calls := applyCalls(t, api, p); len(calls) != 0 {
		t.Fatalf("Apply made calls %q", calls)
	}
}

func TestPlanReplacesForeignOrMissingKey(t *testing.T) {
	for _, keyAccount := range []string{"", "a9"} {
		t.Run("key account "+keyAccount, func(t *testing.T) {
			api := twoKeyAPI()
			p := inspect(t, api, responseInputs(api, keyAccount, nil))
			if got, want := responseStates(p), []State{Done, Done, Change}; !reflect.DeepEqual(got, want) {
				t.Fatalf("states = %v, want %v (%+v)", got, want, p.Steps[7:])
			}
			want := []string{"CreateAPIKey(a1,CSM,127.0.0.1 ::1)", "WriteKey(test-key-1)", "APIKeys", "DeleteAPIKeys(a1,old1,old2)"}
			if calls := applyCalls(t, api, p); !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls = %q, want %q", calls, want)
			}
			if want := []stalwartapi.APIKey{{ID: "id1", Description: "CSM"}}; !reflect.DeepEqual(api.keys["a1"], want) {
				t.Fatalf("keys = %+v, want only the new one", api.keys["a1"])
			}
		})
	}
}

func TestKeyStepRemovesKeyWhenFileWriteFails(t *testing.T) {
	api := twoKeyAPI()
	writeErr := errors.New("disk full")
	p := inspect(t, api, responseInputs(api, "", writeErr))
	api.calls = nil
	_, err := p.Apply(context.Background(), api)
	if !errors.Is(err, writeErr) || errors.Is(err, ErrSettingsWrite) || !strings.Contains(err.Error(), "response key") {
		t.Fatalf("err = %v, want the write error naming the step, not a settings write", err)
	}
	want := []string{"CreateAPIKey(a1,CSM,127.0.0.1 ::1)", "WriteKey(test-key-1)", "DeleteAPIKeys(a1,id1)"}
	if !reflect.DeepEqual(api.calls, want) {
		t.Fatalf("calls = %q, want %q", api.calls, want)
	}
	if want := []stalwartapi.APIKey{{ID: "old1", Description: "CSM"}, {ID: "old2", Description: "CSM"}}; !reflect.DeepEqual(api.keys["a1"], want) {
		t.Fatalf("keys = %+v, want the old keys kept", api.keys["a1"])
	}
}

// The new key is in the file and works, so a failed clean-up keeps it, and
// the next run, whose key file names a1, finishes the clean-up.
func TestKeyStepKeepsNewKeyWhenOldKeysStay(t *testing.T) {
	api := twoKeyAPI()
	p := inspect(t, api, responseInputs(api, "", nil))
	api.failOn = "DeleteAPIKeys"
	api.calls = nil
	_, err := p.Apply(context.Background(), api)
	if err == nil || !strings.Contains(err.Error(), "older keys") {
		t.Fatalf("err = %v, want the older keys named", err)
	}
	if len(api.keys["a1"]) != 3 || slices.Contains(api.calls, "DeleteAPIKeys(a1,id1)") {
		t.Fatalf("keys = %+v, calls %q; want the new key kept", api.keys["a1"], api.calls)
	}

	api.failOn = ""
	p = inspect(t, api, responseInputs(api, "a1", nil))
	if got, want := responseStates(p), []State{Done, Done, Change}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rerun states = %v, want %v (%+v)", got, want, p.Steps[7:])
	}
	applyCalls(t, api, p)
	if want := []stalwartapi.APIKey{{ID: "id2", Description: "CSM"}}; !reflect.DeepEqual(api.keys["a1"], want) {
		t.Fatalf("rerun keys = %+v, want only the newest", api.keys["a1"])
	}
}

// Secrets are not listed, so CSM cannot tell which of several keys is in
// its file; it replaces them all.
func TestPlanReplacesKeyWhenAccountHasExtraKeys(t *testing.T) {
	api := twoKeyAPI()
	p := inspect(t, api, responseInputs(api, "a1", nil))
	if got, want := responseStates(p), []State{Done, Done, Change}; !reflect.DeepEqual(got, want) {
		t.Fatalf("states = %v, want %v (%+v)", got, want, p.Steps[7:])
	}
	if s := p.Steps[9]; !strings.Contains(s.Detail, "extra") {
		t.Fatalf("key step = %+v, want the extra keys named", s)
	}
	want := []string{"CreateAPIKey(a1,CSM,127.0.0.1 ::1)", "WriteKey(test-key-1)", "APIKeys", "DeleteAPIKeys(a1,old1,old2)"}
	if calls := applyCalls(t, api, p); !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %q, want %q", calls, want)
	}
	if want := []stalwartapi.APIKey{{ID: "id1", Description: "CSM"}}; !reflect.DeepEqual(api.keys["a1"], want) {
		t.Fatalf("keys = %+v, want only the new one", api.keys["a1"])
	}

	api = preparedAPI()
	api.keys["a1"] = nil
	if s := inspect(t, api, responseInputs(api, "a1", nil)).Steps[9]; s.State != Change {
		t.Fatalf("no keys listed: key step = %+v, want Change", s)
	}
}

func TestPlanUpdatesRoleMissingPermission(t *testing.T) {
	for name, mutate := range map[string]func(*stalwartapi.Role){
		"missing permission": func(r *stalwartapi.Role) {
			r.Enabled = slices.DeleteFunc(r.Enabled, func(p string) bool { return p == "sysBlockedIpDestroy" })
		},
		"missing User role": func(r *stalwartapi.Role) { r.RoleIDs = nil },
	} {
		t.Run(name, func(t *testing.T) {
			api := preparedAPI()
			mutate(&api.roles[1])
			p := inspect(t, api, responseInputs(api, "a1", nil))
			if got, want := responseStates(p), []State{Change, Done, Done}; !reflect.DeepEqual(got, want) {
				t.Fatalf("states = %v, want %v (%+v)", got, want, p.Steps[7:])
			}
			// The save replaces the role, so the step must not promise to add.
			if d := p.Steps[7].Detail; !strings.Contains(d, "; reset it to CSM's permissions and the User role") {
				t.Fatalf("role step detail = %q, want it to say the role is reset", d)
			}
			if calls := applyCalls(t, api, p); !reflect.DeepEqual(calls, []string{"SaveRole(r1," + ResponseRole + ")"}) {
				t.Fatalf("calls = %q", calls)
			}
			if r := api.roles[1]; !reflect.DeepEqual(r.Enabled, ResponsePermissions) || !reflect.DeepEqual(r.RoleIDs, []string{"u"}) {
				t.Fatalf("role = %+v, want the full list and the User role", r)
			}
		})
	}
}

func TestPlanResetsAccountRole(t *testing.T) {
	api := preparedAPI()
	api.acctRoles["a1"] = []string{"r1", "u"}
	p := inspect(t, api, responseInputs(api, "a1", nil))
	if got, want := responseStates(p), []State{Done, Change, Done}; !reflect.DeepEqual(got, want) {
		t.Fatalf("states = %v, want %v (%+v)", got, want, p.Steps[7:])
	}
	if calls := applyCalls(t, api, p); !reflect.DeepEqual(calls, []string{"SetAccountRole(a1,r1)"}) {
		t.Fatalf("calls = %q", calls)
	}
}

func TestPlanNeedsDomainChoice(t *testing.T) {
	twoDomains := func() *fakeAPI {
		api := responseAPI()
		api.domains = append(api.domains, stalwartapi.Domain{ID: "d2", Name: "example.net", Aliases: []string{"example.com"}})
		return api
	}
	api := twoDomains()
	p := inspect(t, api, responseInputs(api, "", nil))
	if s := p.Steps[8]; s.State != Skipped || !strings.Contains(s.Detail, "--account-domain") {
		t.Fatalf("account step = %+v, want Skipped naming --account-domain", s)
	}
	if s := p.Steps[9]; s.State != Skipped {
		t.Fatalf("key step = %+v, want Skipped", s)
	}

	for _, domain := range []string{"example.net", "EXAMPLE.Net"} {
		api = twoDomains()
		in := responseInputs(api, "", nil)
		in.AccountDomain = domain
		p = inspect(t, api, in)
		if got, want := responseStates(p), []State{Change, Change, Change}; !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: states = %v, want %v (%+v)", domain, got, want, p.Steps[7:])
		}
		if calls := applyCalls(t, api, p); !slices.Contains(calls, "CreateAccount(csm-response,d2,id1)") {
			t.Fatalf("%s: calls = %q, want the account created in example.net", domain, calls)
		}
	}

	// A domain alias is not a domain, and a Unicode fold is not ASCII case:
	// the Kelvin sign folds to k.
	for _, domain := range []string{"example.com", "\u212aiosk.example.net", "kios\u212a.example.net"} {
		api = twoDomains()
		api.domains = append(api.domains, stalwartapi.Domain{ID: "d3", Name: "kiosk.example.net"})
		in := responseInputs(api, "", nil)
		in.AccountDomain = domain
		p = inspect(t, api, in)
		if s := p.Steps[8]; s.State != Skipped || !strings.Contains(s.Detail, "no domain named") {
			t.Fatalf("%q: account step = %+v, want Skipped saying there is no such domain", domain, s)
		}
		if calls := applyCalls(t, api, p); slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, "CreateAccount") }) {
			t.Fatalf("%q: calls = %q, want no account created", domain, calls)
		}
	}
}

func TestPlanWarnsOnDuplicateResponseAccount(t *testing.T) {
	api := preparedAPI()
	api.accounts = append(api.accounts, stalwartapi.Account{ID: "a2", Name: ResponseAccount, Email: "csm-response@example.net"})
	p := inspect(t, api, responseInputs(api, "a1", nil))
	s := p.Steps[8]
	if s.State != Warn || !strings.Contains(s.Detail, "csm-response@example.org") || !strings.Contains(s.Detail, "csm-response@example.net") {
		t.Fatalf("account step = %+v, want Warn naming both accounts", s)
	}
	if p.Steps[9].State != Skipped {
		t.Fatalf("key step = %+v, want Skipped", p.Steps[9])
	}
	if calls := applyCalls(t, api, p); len(calls) != 0 {
		t.Fatalf("Apply made calls %q", calls)
	}
}

func TestPlanSkipsKeyStepsForRemoteAPI(t *testing.T) {
	api := responseAPI()
	in := responseInputs(api, "", nil)
	in.LocalAPI = false
	p := inspect(t, api, in)
	for _, s := range p.Steps[7:] {
		if s.State != Skipped || !strings.Contains(s.Detail, "not on this host") {
			t.Fatalf("step = %+v, want Skipped saying the API is not on this host", s)
		}
	}
	if slices.Contains(api.calls, "RoleByDescription") {
		t.Fatalf("calls = %q, want no response reads", api.calls)
	}
}

func TestPlanWarnsWithoutUserRole(t *testing.T) {
	api := responseAPI()
	api.roles = nil
	p := inspect(t, api, responseInputs(api, "", nil))
	if got, want := responseStates(p), []State{Warn, Skipped, Skipped}; !reflect.DeepEqual(got, want) {
		t.Fatalf("states = %v, want %v (%+v)", got, want, p.Steps[7:])
	}
	if !strings.Contains(p.Steps[7].Detail, `"User"`) {
		t.Fatalf("role step = %+v, want the User role named", p.Steps[7])
	}
	if calls := applyCalls(t, api, p); len(calls) != 0 {
		t.Fatalf("Apply made calls %q", calls)
	}
}

// The response steps write no Stalwart setting, so they need no reload; a
// settings change in the same run still gets one, after every write.
func TestPlanResponseStepsReloadOnlyForSettings(t *testing.T) {
	api := responseAPI()
	api.levels = nil
	p := inspect(t, api, responseInputs(api, "", nil))
	calls := applyCalls(t, api, p)
	if slices.Index(calls, "ReloadSettings") != len(calls)-1 || !slices.Contains(calls, "WriteKey(test-key-1)") {
		t.Fatalf("calls = %q, want one reload after every write", calls)
	}
}

// responseState is the fake's role, account and key state, to show a run
// changed nothing.
func responseState(api *fakeAPI) string {
	return fmt.Sprintf("%+v %+v %+v %+v", api.roles, api.accounts, api.acctRoles, api.keys)
}

// foreignAccountPlan inspects and applies a plan for an existing csm-response
// account and checks the account step warns with want, the key step is
// skipped and nothing was written.
func foreignAccountPlan(t *testing.T, api *fakeAPI, want string) {
	t.Helper()
	before := responseState(api)
	p := inspect(t, api, responseInputs(api, "", nil))
	if s := p.Steps[8]; s.State != Warn || !strings.Contains(s.Detail, want) {
		t.Fatalf("account step = %+v, want Warn saying %q", s, want)
	}
	if s := p.Steps[9]; s.State != Skipped {
		t.Fatalf("key step = %+v, want Skipped", s)
	}
	if calls := applyCalls(t, api, p); len(calls) != 0 {
		t.Fatalf("Apply made calls %q", calls)
	}
	if after := responseState(api); after != before {
		t.Fatalf("state changed:\n%s\n%s", before, after)
	}
}

func TestPlanWarnsOnAccountWithSignInStopped(t *testing.T) {
	api := preparedAPI()
	api.accounts[0].SignInDisabled = true
	api.creds = map[string][]string{"a1": {"ApiKey"}}
	foreignAccountPlan(t, api, "sign-ins are stopped")
}

func TestPlanWarnsOnAccountWithPassword(t *testing.T) {
	for name, roles := range map[string][]string{"response role": {"r1"}, "other role": {"u"}} {
		for _, kind := range []string{"Password", "AppPassword"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				api := preparedAPI()
				api.acctRoles["a1"] = roles
				api.creds = map[string][]string{"a1": {"ApiKey", kind}}
				foreignAccountPlan(t, api, "has a password")
			})
		}
	}
}

func TestPlanWarnsOnForeignAccountWithKey(t *testing.T) {
	api := preparedAPI()
	api.acctRoles["a1"] = []string{"u"}
	api.creds = map[string][]string{"a1": {"ApiKey"}}
	foreignAccountPlan(t, api, "CSM did not make")
}

func TestPlanAdoptsEmptyAccount(t *testing.T) {
	api := preparedAPI()
	api.acctRoles["a1"] = []string{"u"}
	api.keys["a1"] = nil
	p := inspect(t, api, responseInputs(api, "", nil))
	if got, want := responseStates(p), []State{Done, Change, Change}; !reflect.DeepEqual(got, want) {
		t.Fatalf("states = %v, want %v (%+v)", got, want, p.Steps[7:])
	}
	if calls := applyCalls(t, api, p); len(calls) == 0 || calls[0] != "SetAccountRole(a1,r1)" {
		t.Fatalf("calls = %q, want the role set first", calls)
	}
	if !reflect.DeepEqual(api.acctRoles["a1"], []string{"r1"}) {
		t.Fatalf("roles = %v, want the response role only", api.acctRoles["a1"])
	}
}

// Only keys are safe on CSM's account: any other kind, including one Stalwart
// adds later or an entry with no kind, may sign in from anywhere.
func TestPlanWarnsOnUnknownCredentialKind(t *testing.T) {
	for _, creds := range [][]string{{"ApiKey", "Totp"}, {""}, {"ApiKey", "x\x1b[2J"}} {
		t.Run(fmt.Sprintf("%q", creds), func(t *testing.T) {
			api := preparedAPI()
			api.creds = map[string][]string{"a1": creds}
			foreignAccountPlan(t, api, "sign-in credential CSM does not know")
			if d := inspect(t, api, responseInputs(api, "", nil)).Steps[8].Detail; strings.Contains(d, "\x1b") {
				t.Fatalf("detail %q prints a raw credential kind", d)
			}
		})
	}
}

// Package callers must not receive the newly created secret on any error.
func TestReplaceKeyRedactsNewSecret(t *testing.T) {
	for _, stage := range []string{"write", "list", "delete"} {
		t.Run(stage, func(t *testing.T) {
			api := twoKeyAPI()
			write := func(secret string) error {
				switch stage {
				case "write":
					return errors.New("write failed: " + secret)
				case "list":
					api.readErrors = map[string]error{"APIKeys": errors.New("list failed: " + secret)}
				case "delete":
					api.writeErr = errors.New("delete failed: " + secret)
				}
				return nil
			}
			err := replaceKey(context.Background(), api, "a1", write)
			if err == nil {
				t.Fatal("failure reported success")
			}
			if strings.Contains(err.Error(), "test-key-1") {
				t.Fatal("replacement error exposed the new secret")
			}
		})
	}
}

func TestResponseRoleClearsPermissionDenials(t *testing.T) {
	api := preparedAPI()
	for i := range api.roles {
		if api.roles[i].Description == ResponseRole {
			api.roles[i].Disabled = []string{"authenticate"}
		}
	}
	p := inspect(t, api, responseInputs(api, "a1", nil))
	if p.Steps[7].State != Change {
		t.Fatal("role denying sign-in was treated as ready")
	}
	if _, err := p.Apply(context.Background(), api); err != nil {
		t.Fatal(err)
	}
	for _, r := range api.roles {
		if r.Description == ResponseRole && len(r.Disabled) != 0 {
			t.Fatal("role still denies sign-in")
		}
	}
	p = inspect(t, api, responseInputs(api, "a1", nil))
	if got := responseStates(p); !reflect.DeepEqual(got, []State{Done, Done, Done}) {
		t.Fatalf("rerun response states = %v, want all done", got)
	}
	if calls := applyCalls(t, api, p); len(calls) != 0 {
		t.Fatal("rerun changed the repaired response role")
	}
}

// addressListWrites are the writes that create CSM's tags, at CSM's scores,
// then its rule.
var addressListWrites = []string{
	"CreateSpamTag(CSM_IP_DROP,4)", "CreateSpamTag(CSM_IP_BLOCKED,3)", "CreateSpamTag(CSM_IP_MAIL_AUTH,3)", "CreateSpamTag(CSM_IP_SPAM,3)",
	"CreateSpamTag(CSM_IP_BLOCKLISTDE,2)", "CreateSpamTag(CSM_IP_CINS,2)", "CreateSpamTag(CSM_IP_CANARY,0)",
	"CreateSpamRule(CSM_IP)",
}

const addressListDone = "rule CSM_IP adds CSM_IP_DROP 4, CSM_IP_BLOCKED 3, CSM_IP_MAIL_AUTH 3, CSM_IP_SPAM 3, CSM_IP_BLOCKLISTDE 2, CSM_IP_CINS 2, CSM_IP_CANARY 0 to senders on CSM's address list"

const addressListCreate = "create rule CSM_IP: Stalwart adds up to 4 to the spam score of senders on CSM's address list, so more of their mail goes to Junk, or is rejected or discarded at the scores set in Stalwart; switch the rule off in Stalwart to stop"
const addressListOff = "rule CSM_IP is switched off in Stalwart, so CSM's address list adds no score"

func TestAddressListArms(t *testing.T) {
	arms := AddressListArms()
	symbols := ipmap.Symbols()
	if len(arms) != 7 || len(symbols) != 7 {
		t.Fatalf("%d arms for %d symbols, want 7", len(arms), len(symbols))
	}
	want := stalwartapi.RuleArm{
		If:   "key_exists('csm-ip-drop', remote_ip) || (is_ipv6_addr(remote_ip) && key_exists('csm-ip6-drop', ip_reverse_name(remote_ip)))",
		Then: "'CSM_IP_DROP'",
	}
	if arms[0] != want {
		t.Fatalf("arm 0 = %+v, want %+v", arms[0], want)
	}
	for i, s := range symbols {
		v4 := "key_exists('" + ipmap.StalwartNamespace(s, false) + "', remote_ip)"
		v6 := "key_exists('" + ipmap.StalwartNamespace(s, true) + "', ip_reverse_name(remote_ip))"
		if arms[i].Then != "'"+s.Name+"'" || !strings.Contains(arms[i].If, v4) || !strings.Contains(arms[i].If, v6) {
			t.Errorf("arm %d = %+v, want %s from its two namespaces", i, arms[i], s.Name)
		}
	}
}

func TestAddressListStepCreates(t *testing.T) {
	api := configuredAPI()
	api.rules, api.tags = nil, nil
	p := inspect(t, api, fieldInputs())
	s := stepNamed(t, p, "address list")
	if s.State != Change || p.AddressListOn {
		t.Fatalf("step = %+v, on %v; want Change and the list off", s, p.AddressListOn)
	}
	if s.Detail != addressListCreate {
		t.Errorf("detail = %q, want %q", s.Detail, addressListCreate)
	}
	if calls, want := applyCalls(t, api, p), append(slices.Clone(addressListWrites), "ReloadSettings"); !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %q, want %q", calls, want)
	}
	want := stalwartapi.SpamRule{ID: "rule-CSM_IP", Type: "Any", Enabled: true, Arms: AddressListArms(), Else: "false"}
	if got := api.rules[AddressListRule]; !reflect.DeepEqual(got, want) {
		t.Fatalf("rule = %+v, want %+v", got, want)
	}

	p = inspect(t, api, fieldInputs())
	if s := stepNamed(t, p, "address list"); s.State != Done || s.Detail != addressListDone || !p.AddressListOn {
		t.Fatalf("second run: step = %+v, on %v; want Done with every tag and the list on", s, p.AddressListOn)
	}
	if calls := applyCalls(t, api, p); len(calls) != 0 {
		t.Fatalf("second run made calls %q", calls)
	}
}

// The rule's own switch is the operator's: setup never turns it back on and
// never rewrites a rule that is off.
func TestAddressListStepOffIsDone(t *testing.T) {
	api := configuredAPI()
	r := api.rules[AddressListRule]
	r.Enabled, r.Arms = false, r.Arms[:2]
	api.rules[AddressListRule] = r
	delete(api.tags, "CSM_IP_CINS")
	p := inspect(t, api, fieldInputs())
	if s := stepNamed(t, p, "address list"); s.State != Done || s.Detail != addressListOff || p.AddressListOn {
		t.Fatalf("step = %+v, on %v; want Done saying it is switched off, and the list off", s, p.AddressListOn)
	}
	if calls := applyCalls(t, api, p); len(calls) != 0 {
		t.Fatalf("Apply made calls %q", calls)
	}
}

func TestAddressListStepResetsCondition(t *testing.T) {
	for name, mutate := range map[string]func(*stalwartapi.SpamRule){
		"arms":     func(r *stalwartapi.SpamRule) { r.Arms[3].If = "true" },
		"arm gone": func(r *stalwartapi.SpamRule) { r.Arms = r.Arms[:6] },
		"else":     func(r *stalwartapi.SpamRule) { r.Else = "'CSM_IP_DROP'" },
	} {
		t.Run(name, func(t *testing.T) {
			api := configuredAPI()
			r := api.rules[AddressListRule]
			r.Arms = slices.Clone(r.Arms)
			mutate(&r)
			api.rules[AddressListRule] = r
			p := inspect(t, api, fieldInputs())
			if s := stepNamed(t, p, "address list"); s.State != Change || !p.AddressListOn {
				t.Fatalf("step = %+v, on %v; want Change and the list on", s, p.AddressListOn)
			}
			if calls := applyCalls(t, api, p); !reflect.DeepEqual(calls, []string{"SetSpamRuleCondition(rule1)", "ReloadSettings"}) {
				t.Fatalf("calls = %q, want only the condition reset and a reload", calls)
			}
			want := stalwartapi.SpamRule{ID: "rule1", Type: "Any", Enabled: true, Arms: AddressListArms(), Else: "false"}
			if got := api.rules[AddressListRule]; !reflect.DeepEqual(got, want) {
				t.Fatalf("rule = %+v, want %+v", got, want)
			}
		})
	}
}

// Scores are Stalwart's knobs: setup creates a missing tag and leaves an
// existing one as it is.
func TestAddressListStepKeepsOperatorTags(t *testing.T) {
	api := configuredAPI()
	drop := api.tags["CSM_IP_DROP"]
	drop.Score = 1
	api.tags["CSM_IP_DROP"] = drop
	p := inspect(t, api, fieldInputs())
	want := strings.Replace(addressListDone, "CSM_IP_DROP 4", "CSM_IP_DROP 1", 1)
	if s := stepNamed(t, p, "address list"); s.State != Done || s.Detail != want {
		t.Fatalf("step = %+v, want Done %q", s, want)
	}
	if calls := applyCalls(t, api, p); len(calls) != 0 {
		t.Fatalf("Apply made calls %q", calls)
	}

	delete(api.tags, "CSM_IP_SPAM")
	p = inspect(t, api, fieldInputs())
	if s := stepNamed(t, p, "address list"); s.State != Change || s.Detail != "create the missing tag CSM_IP_SPAM" {
		t.Fatalf("missing tag: step = %+v, want Change naming CSM_IP_SPAM", s)
	}
	if calls := applyCalls(t, api, p); !reflect.DeepEqual(calls, []string{"CreateSpamTag(CSM_IP_SPAM,3)", "ReloadSettings"}) {
		t.Fatalf("missing tag: calls = %q, want only that tag created", calls)
	}
	if got := api.tags["CSM_IP_DROP"]; got != drop {
		t.Fatalf("operator tag = %+v, want %+v", got, drop)
	}
}

func TestAddressListStepForeignType(t *testing.T) {
	api := configuredAPI()
	r := api.rules[AddressListRule]
	r.Type = "Ip"
	api.rules[AddressListRule] = r
	p := inspect(t, api, fieldInputs())
	if s := stepNamed(t, p, "address list"); s.State != Warn || s.apply != nil || p.AddressListOn {
		t.Fatalf("step = %+v, on %v; want a read-only Warn and the list off", s, p.AddressListOn)
	}
	if calls := applyCalls(t, api, p); len(calls) != 0 {
		t.Fatalf("Apply made calls %q", calls)
	}
}

// A key from before the address list may not read rules or tags: the step
// warns and setup still plans everything else.
func TestAddressListStepForbiddenIsWarn(t *testing.T) {
	for _, method := range []string{"SpamRule", "SpamTag"} {
		t.Run(method, func(t *testing.T) {
			api := freshAPI()
			api.readErrors = map[string]error{method: fmt.Errorf("x:%s/query: %w", method, stalwartapi.ErrForbidden)}
			p := inspect(t, api, fieldInputs())
			if got, want := states(p), []State{Change, Change, Change, Done, Change, Done, Warn, Skipped, Skipped, Skipped}; !reflect.DeepEqual(got, want) {
				t.Fatalf("states = %v, want %v", got, want)
			}
			s := stepNamed(t, p, "address list")
			if s.Detail != "Cannot read Stalwart's spam rules; run csm stalwart setup with an admin login" || s.apply != nil {
				t.Fatalf("step = %+v, want the static read-only warning", s)
			}
		})
	}
}

func TestAddressListStepUnauthorizedStopsSetup(t *testing.T) {
	for _, method := range []string{"SpamRule", "SpamTag"} {
		t.Run(method, func(t *testing.T) {
			api := configuredAPI()
			api.readErrors = map[string]error{method: fmt.Errorf("login: %w", stalwartapi.ErrUnauthorized)}
			p, err := Inspect(context.Background(), api, fieldInputs())
			if !errors.Is(err, stalwartapi.ErrUnauthorized) || len(p.Steps) != 0 {
				t.Fatalf("Inspect = %d steps, %v; want the login error and no plan", len(p.Steps), err)
			}
		})
	}
}

func TestResponsePermissionsIncludeAddressList(t *testing.T) {
	for _, p := range []string{
		"sysMemoryLookupKeyGet", "sysMemoryLookupKeyQuery", "sysMemoryLookupKeyCreate", "sysMemoryLookupKeyDestroy",
		"actionReloadLookupStores", "sysSpamRuleGet", "sysSpamRuleQuery", "sysSpamTagGet", "sysSpamTagQuery",
	} {
		if !slices.Contains(ResponsePermissions, p) {
			t.Errorf("ResponsePermissions lacks %s", p)
		}
	}
}
