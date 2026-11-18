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
	"slices"
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

const (
	setupTestPassword = "s3cret-test"
	setupTestKey      = "API_test-secret-123"
)

// setupFakeAPI is a Stalwart with nothing prepared and one loopback HTTP
// listener on 8080.
type setupFakeAPI struct {
	http      stalwartapi.HTTPSettings
	spam      stalwartapi.SpamSettings
	stageOff  bool
	spamErr   error
	stageErr  error
	readErr   error
	writeErr  error
	deleteErr error
	reloadErr error
	writes    []string
	probe     stalwartapi.SpamProbeResult
	probeErr  error
	probes    []stalwartapi.SpamProbe

	// Stalwart's User role, CSM's role, csm-response and its keys.
	userRole  bool
	role      *stalwartapi.Role
	account   *stalwartapi.Account
	acctRoles []string
	keys      []stalwartapi.APIKey
	creds     []string
	secret    string

	// session and sessionErr answer SessionAccount.
	session    string
	sessionErr error

	// CSM's address list rule and its tags.
	rule *stalwartapi.SpamRule
	tags map[string]stalwartapi.SpamTag
}

func (f *setupFakeAPI) SessionAccount(context.Context) (string, error) {
	return f.session, f.sessionErr
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
func (f *setupFakeAPI) SpamSettings(context.Context) (stalwartapi.SpamSettings, error) {
	return f.spam, errors.Join(f.readErr, f.spamErr)
}
func (f *setupFakeAPI) SpamFilterStageOff(context.Context) (bool, error) {
	return f.stageOff, errors.Join(f.readErr, f.stageErr)
}
func (f *setupFakeAPI) ClassifySpam(_ context.Context, p stalwartapi.SpamProbe) (stalwartapi.SpamProbeResult, error) {
	f.probes = append(f.probes, p)
	return f.probe, f.probeErr
}
func (f *setupFakeAPI) ReloadSettings(context.Context) ([]string, error) {
	f.writes = append(f.writes, "reload")
	return []string{"store: reloaded with a note"}, f.reloadErr
}
func (f *setupFakeAPI) RoleByDescription(_ context.Context, description string) (stalwartapi.Role, bool, error) {
	switch {
	case description == "User" && f.userRole:
		return stalwartapi.Role{ID: "u", Description: "User"}, true, f.readErr
	case description == stalwartsetup.ResponseRole && f.role != nil:
		return *f.role, true, f.readErr
	}
	return stalwartapi.Role{}, false, f.readErr
}
func (f *setupFakeAPI) SaveRole(_ context.Context, r stalwartapi.Role) (string, error) {
	f.writes = append(f.writes, "role")
	r.ID = "r1"
	f.role = &r
	return r.ID, f.writeErr
}
func (f *setupFakeAPI) Domains(context.Context) ([]stalwartapi.Domain, error) {
	return []stalwartapi.Domain{{ID: "d1", Name: "example.org"}}, f.readErr
}
func (f *setupFakeAPI) AccountsNamed(context.Context, string) ([]stalwartapi.Account, error) {
	if f.account == nil {
		return nil, f.readErr
	}
	return []stalwartapi.Account{*f.account}, f.readErr
}
func (f *setupFakeAPI) AccountRoleIDs(context.Context, string) ([]string, error) {
	return f.acctRoles, f.readErr
}
func (f *setupFakeAPI) AccountCredentialTypes(context.Context, string) ([]string, error) {
	return f.creds, f.readErr
}
func (f *setupFakeAPI) CreateAccount(_ context.Context, name, _, roleID string) (string, error) {
	f.writes = append(f.writes, "account")
	f.account = &stalwartapi.Account{ID: "a1", Name: name, Email: name + "@example.org"}
	f.acctRoles = []string{roleID}
	return "a1", f.writeErr
}
func (f *setupFakeAPI) SetAccountRole(_ context.Context, _, roleID string) error {
	f.writes = append(f.writes, "account role")
	f.acctRoles = []string{roleID}
	return f.writeErr
}
func (f *setupFakeAPI) APIKeys(context.Context, string) ([]stalwartapi.APIKey, error) {
	return f.keys, f.readErr
}
func (f *setupFakeAPI) CreateAPIKey(context.Context, string, string, []string) (string, string, error) {
	f.writes = append(f.writes, "key")
	f.keys = append(f.keys, stalwartapi.APIKey{ID: "k-new", Description: "CSM"})
	return "k-new", f.secret, f.writeErr
}
func (f *setupFakeAPI) DeleteAPIKeys(_ context.Context, _ string, ids []string) error {
	f.writes = append(f.writes, "delete keys "+strings.Join(ids, ","))
	return errors.Join(f.writeErr, f.deleteErr)
}

func (f *setupFakeAPI) SpamRule(context.Context, string) (stalwartapi.SpamRule, bool, error) {
	if f.rule == nil {
		return stalwartapi.SpamRule{}, false, f.readErr
	}
	return *f.rule, true, f.readErr
}
func (f *setupFakeAPI) CreateSpamRule(_ context.Context, _ string, r stalwartapi.SpamRule) error {
	f.writes = append(f.writes, "spam rule")
	f.rule = &stalwartapi.SpamRule{ID: "rule1", Type: "Any", Enabled: true, Arms: r.Arms, Else: r.Else}
	return f.writeErr
}
func (f *setupFakeAPI) SetSpamRuleCondition(_ context.Context, _ string, arms []stalwartapi.RuleArm, elseExpr string) error {
	f.writes = append(f.writes, "rule condition")
	f.rule.Arms, f.rule.Else = arms, elseExpr
	return f.writeErr
}
func (f *setupFakeAPI) SpamTag(_ context.Context, tag string) (stalwartapi.SpamTag, bool, error) {
	t, ok := f.tags[tag]
	return t, ok, f.readErr
}
func (f *setupFakeAPI) CreateSpamTag(_ context.Context, tag string, score float64) error {
	f.writes = append(f.writes, "spam tag")
	if f.tags == nil {
		f.tags = map[string]stalwartapi.SpamTag{}
	}
	f.tags[tag] = stalwartapi.SpamTag{ID: "tag-" + tag, Type: "Score", Tag: tag, Score: score}
	return f.writeErr
}

// settingsSetupWrites are setup's writes to a fresh Stalwart whose response
// steps are done: four settings, CSM's seven tags and rule, then one reload.
func settingsSetupWrites() []string {
	w := []string{"tracing", "http", "bans", "tracing"}
	for range 7 {
		w = append(w, "spam tag")
	}
	return append(w, "spam rule", "reload")
}

// prepare gives the fake the User role and, with done, CSM's role and
// account as setup leaves them.
func (f *setupFakeAPI) prepare(done bool) {
	f.userRole = true
	f.secret = setupTestKey
	if done {
		f.role = &stalwartapi.Role{ID: "r1", Description: stalwartsetup.ResponseRole, Enabled: stalwartsetup.ResponsePermissions, RoleIDs: []string{"u"}}
		f.account = &stalwartapi.Account{ID: "a1", Name: stalwartsetup.ResponseAccount, Email: "csm-response@example.org"}
		f.acctRoles = []string{"r1"}
		f.keys = []stalwartapi.APIKey{{ID: "k1", Description: "CSM"}}
	}
}

type setupHarness struct {
	deps    stalwartSetupDeps
	api     *setupFakeAPI
	env     map[string]string
	gotURL  string
	gotUser string
	gotPass string
	cfg     *config.Config

	// keyAccount and keyErr answer the key probe; gotKey is the key it got.
	keyAccount string
	keyErr     error
	gotKey     string
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
		api: &setupFakeAPI{http: stalwartapi.HTTPSettings{ClientIPSource: "peer", ForwardedHops: 1}, spam: stalwartapi.SpamSettings{Enabled: true, ScoreSpam: 5}},
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
		keyAccount: func(_ context.Context, _, key string) (string, error) {
			h.gotKey = key
			return h.keyAccount, h.keyErr
		},
	}
	h.cfg = cfg
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
	h := newDoctorKeyHarness(t)
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

func TestStalwartSetupPrintsSpamSteps(t *testing.T) {
	h := newDoctorKeyHarness(t)
	code, out := h.run("--dry-run")
	if code != 0 || !strings.Contains(out, "spam verdict logging: change: ") || !strings.Contains(out, "spam filter: done: ") {
		t.Fatalf("code %d, out %q; want 0 with both spam steps", code, out)
	}

	h = newDoctorKeyHarness(t)
	h.api.spam.Enabled = false
	if code, out := h.run("--dry-run"); code != 0 || !strings.Contains(out, "spam filter: warn: ") {
		t.Fatalf("filter off: code %d, out %q; want 0 with the spam filter warned", code, out)
	}
}

func TestStalwartSetupAppliesAndReloadsOnce(t *testing.T) {
	h := newDoctorKeyHarness(t)
	code, out := h.run("--url", "http://127.0.0.1:18080")
	if code != 0 {
		t.Fatalf("code = %d, out %q", code, out)
	}
	if want := settingsSetupWrites(); !reflect.DeepEqual(h.api.writes, want) {
		t.Fatalf("writes = %q, want %q", h.api.writes, want)
	}
	if h.gotURL != "http://127.0.0.1:18080" {
		t.Fatalf("--url ignored: %q", h.gotURL)
	}
	for _, want := range []string{"failed-login logging: changed: ", "ban expiry: changed: ", "12h", "address list: changed: ", "store: reloaded with a note"} {
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
			h := newDoctorKeyHarness(t)
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
	h := newDoctorKeyHarness(t)
	h.api.http = stalwartapi.HTTPSettings{ClientIPSource: "xForwardedFor", ForwardedHops: 1}
	h.deps.readStatus = func() ([]byte, error) { return nil, errors.New("down") }
	if code, out := h.run("--dry-run"); code != 1 || !strings.Contains(out, "unsafe") {
		t.Fatalf("unsafe: code %d, out %q; want 1", code, out)
	}

	h = newDoctorKeyHarness(t)
	h.api.writeErr = errors.New("refused")
	if code, out := h.run(); code != 1 || !strings.Contains(out, "refused") {
		t.Fatalf("write error: code %d, out %q; want 1", code, out)
	}

	h = newDoctorKeyHarness(t)
	h.deps.readStatus = func() ([]byte, error) { return nil, errors.New("down") }
	if code, out := h.run(); code != 0 {
		t.Fatalf("skipped step: code %d, out %q; want 0", code, out)
	}

	h = newDoctorKeyHarness(t)
	h.api.readErr = fmt.Errorf("stalwart /jmap/: %w", stalwartapi.ErrUnauthorized)
	if code, _ := h.run(); code != 2 {
		t.Fatalf("refused login: code %d, want 2", code)
	}

	h = newDoctorKeyHarness(t)
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

func TestStalwartSetupSpamReadFailures(t *testing.T) {
	for _, method := range []string{"settings", "stage"} {
		for _, dryRun := range []bool{true, false} {
			for _, unauthorized := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/dry=%t/unauthorized=%t", method, dryRun, unauthorized), func(t *testing.T) {
					// CSM's account and key are in place, so only the spam status warns.
					h := newDoctorKeyHarness(t)
					err := errors.New("API error " + setupTestPassword)
					if unauthorized {
						err = fmt.Errorf("%s: %w", setupTestPassword, stalwartapi.ErrUnauthorized)
					}
					if method == "settings" {
						h.api.spamErr = err
					} else {
						h.api.stageErr = err
					}
					var args []string
					if dryRun {
						args = []string{"--dry-run"}
					}
					code, out := h.run(args...)
					if strings.Contains(out, setupTestPassword) {
						t.Fatal("setup exposed the password")
					}
					if unauthorized {
						if code != 2 || !strings.Contains(out, "refused the admin login") || len(h.api.writes) != 0 {
							t.Fatalf("unauthorized: code %d, writes %q, out %q", code, h.api.writes, out)
						}
						return
					}
					if code != 0 || !strings.Contains(out, "spam filter: warn: Cannot read") {
						t.Fatalf("code %d, out %q; want success with a spam status warning", code, out)
					}
					var want []string
					if !dryRun {
						want = settingsSetupWrites()
					}
					if !reflect.DeepEqual(h.api.writes, want) {
						t.Fatalf("writes = %q, want %q", h.api.writes, want)
					}
				})
			}
		}
	}
}

// useKeyFile points the harness at a key file in a temporary directory,
// holding key when it is not empty.
func (h *setupHarness) useKeyFile(t *testing.T, key string) string {
	t.Helper()
	path := t.TempDir() + "/stalwart-api.key"
	h.cfg.Stalwart.APIKeyFile = path
	if key != "" {
		if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(stalwartapi.SetKeyFileOwnerForTest(uint32(os.Getuid())))
	}
	return path
}

func TestStalwartSetupNeverPrintsKey(t *testing.T) {
	for name, fileWriteFails := range map[string]bool{"success": false, "key file write fails": true} {
		t.Run(name, func(t *testing.T) {
			h := newSetupHarness(t)
			h.api.prepare(false)
			path := h.useKeyFile(t, "")
			if fileWriteFails {
				h.cfg.Stalwart.APIKeyFile = path + "/missing-directory/key"
				// An error that quotes the new key must not print it.
				h.api.deleteErr = errors.New("key " + setupTestKey + " is in use")
			}
			code, out := h.run()
			if strings.Contains(out, setupTestKey) {
				t.Fatalf("output contains the key: %q", out)
			}
			if fileWriteFails {
				if code != 1 || !strings.Contains(out, "response key") || !slices.Contains(h.api.writes, "delete keys k-new") {
					t.Fatalf("code %d, writes %q, out %q; want 1 naming the step, the new key deleted", code, h.api.writes, out)
				}
				if !strings.Contains(out, "key [redacted] is in use") {
					t.Fatalf("out %q; want the delete error printed with the key redacted", out)
				}
				return
			}
			if code != 0 || !strings.Contains(out, "response key: changed: ") {
				t.Fatalf("code %d, out %q; want 0 with the key step changed", code, out)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != setupTestKey {
				t.Fatalf("key file holds the wrong key (%v)", err)
			}
		})
	}
}

func TestStalwartSetupDryRunWritesNoKey(t *testing.T) {
	h := newSetupHarness(t)
	h.api.prepare(false)
	path := h.useKeyFile(t, "")
	code, out := h.run("--dry-run")
	if code != 0 {
		t.Fatalf("code = %d, out %q", code, out)
	}
	for _, want := range []string{"response role: change: ", "response account: change: ", "response key: change: "} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q lacks %q", out, want)
		}
	}
	if len(h.api.writes) != 0 {
		t.Fatalf("dry run wrote %q", h.api.writes)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry run wrote the key file (%v)", err)
	}
}

func TestStalwartSetupReadsExistingKey(t *testing.T) {
	h := newSetupHarness(t)
	h.api.prepare(true)
	h.useKeyFile(t, "test-key-1")
	h.keyAccount = "a1"
	code, out := h.run("--dry-run")
	if code != 0 || h.gotKey != "test-key-1" || !strings.Contains(out, "response key: done: ") {
		t.Fatalf("code %d, out %q; want 0 with the key step done", code, out)
	}
	if strings.Contains(out, "test-key-1") {
		t.Fatalf("output contains the key: %q", out)
	}

	for name, err := range map[string]error{
		"refused":   fmt.Errorf("stalwart /.well-known/jmap: %w", stalwartapi.ErrUnauthorized),
		"forbidden": fmt.Errorf("stalwart /.well-known/jmap: %w", stalwartapi.ErrForbidden),
	} {
		h = newSetupHarness(t)
		h.api.prepare(true)
		h.useKeyFile(t, "test-key-1")
		h.keyErr = err
		if code, out = h.run("--dry-run"); code != 0 || !strings.Contains(out, "response key: change: ") {
			t.Fatalf("%s: code %d, out %q; want 0 with the key step to change", name, code, out)
		}
	}

	h = newSetupHarness(t)
	h.api.prepare(true)
	h.useKeyFile(t, "test-key-1")
	h.keyErr = errors.New("stalwart /.well-known/jmap: HTTP 500 for test-key-1")
	code, out = h.run("--dry-run")
	if code != 1 || strings.Contains(out, "test-key-1") || !strings.Contains(out, "HTTP 500") || h.gotUser != "" {
		t.Fatalf("other error: code %d, admin login sent %v, out %q; want 1 with the error, the key hidden", code, h.gotUser != "", out)
	}
}

// A key file setup cannot trust stops setup instead of being replaced.
func TestStalwartSetupRefusesLooseKeyFile(t *testing.T) {
	h := newSetupHarness(t)
	h.api.prepare(true)
	path := h.useKeyFile(t, "test-key-1")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := h.run("--dry-run")
	if code != 1 || !strings.Contains(out, "0644") || h.gotKey != "" {
		t.Fatalf("code %d, key sent %v, out %q; want 1 naming the mode, no key sent", code, h.gotKey != "", out)
	}
}

// The key works only from this host, so it is never sent to a remote API.
func TestStalwartSetupSendsNoKeyToRemoteAPI(t *testing.T) {
	h := newSetupHarness(t)
	h.api.prepare(true)
	h.useKeyFile(t, "test-key-1")
	code, out := h.run("--url", "https://mail.example.org", "--dry-run")
	if code != 0 || h.gotKey != "" || !strings.Contains(out, "response key: skipped: ") {
		t.Fatalf("code %d, key sent %v, out %q; want 0 with the key steps skipped", code, h.gotKey != "", out)
	}
}

func TestStalwartSetupAccountDomainFlag(t *testing.T) {
	h := newSetupHarness(t)
	h.api.prepare(false)
	h.useKeyFile(t, "")
	if code, out := h.run("--dry-run", "--account-domain", "example.net"); code != 0 || !strings.Contains(out, "response account: skipped: ") || !strings.Contains(out, "example.net") {
		t.Fatalf("code %d, out %q; want the unknown domain named", code, out)
	}
}

// Only a failed settings write leaves settings to reload by hand.
func TestStalwartSetupReloadHintOnlyForSettings(t *testing.T) {
	h := newSetupHarness(t)
	h.api.prepare(false)
	h.cfg.Stalwart.APIKeyFile = h.useKeyFile(t, "") + "/missing-directory/key"
	code, out := h.run()
	if code != 1 || strings.Contains(out, "reload settings") || !strings.Contains(out, "run setup again") {
		t.Fatalf("response step failure: code %d, out %q; want 1 without the reload hint", code, out)
	}

	h = newSetupHarness(t)
	h.api.writeErr = errors.New("refused")
	code, out = h.run()
	if code != 1 || !strings.Contains(out, "reload settings in Stalwart") {
		t.Fatalf("settings failure: code %d, out %q; want 1 with the reload hint", code, out)
	}
}

func TestStalwartSetupWarnsOnAccountWithPassword(t *testing.T) {
	h := newSetupHarness(t)
	h.api.prepare(true)
	h.api.creds = []string{"Password"}
	h.useKeyFile(t, "")
	if code, out := h.run("--dry-run"); code != 1 || !strings.Contains(out, "response account: warn: ") {
		t.Fatalf("dry run: code %d, out %q; want 1 with the account warned", code, out)
	}
	code, out := h.run()
	if code != 1 || !strings.Contains(out, "response account: warn: ") || !strings.Contains(out, "has a password") || !strings.Contains(out, "response key: skipped: ") {
		t.Fatalf("code %d, out %q; want 1 with the account warned and the key skipped", code, out)
	}
	if slices.Contains(h.api.writes, "key") {
		t.Fatalf("writes = %q, want no key created", h.api.writes)
	}
}

func TestStalwartSetupExitStates(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state stalwartsetup.State
		want  int
	}{
		{"response role", stalwartsetup.Warn, 1},
		{"response account", stalwartsetup.Warn, 1},
		{"response key", stalwartsetup.Warn, 1},
		{"spam filter", stalwartsetup.Warn, 0},
		{"proxy protocol listeners", stalwartsetup.Warn, 0},
		{"webmail client addresses", stalwartsetup.Unsafe, 1},
		{"response role", stalwartsetup.Done, 0},
		{"response account", stalwartsetup.Change, 0},
		{"response key", stalwartsetup.Skipped, 0},
	} {
		t.Run(tc.name+"/"+string(tc.state), func(t *testing.T) {
			plan := stalwartsetup.Plan{Steps: []stalwartsetup.Step{{Name: tc.name, State: tc.state}}}
			if got := stalwartSetupExit(plan); got != tc.want {
				t.Fatalf("exit = %d; want %d", got, tc.want)
			}
		})
	}
}

func TestStalwartSetupMissingUserRoleFails(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		t.Run(fmt.Sprint(dryRun), func(t *testing.T) {
			h := newDoctorKeyHarness(t)
			h.api.userRole = false
			var args []string
			if dryRun {
				args = []string{"--dry-run"}
			}
			if code, out := h.run(args...); code != 1 || !strings.Contains(out, "response role: warn: ") {
				t.Fatalf("code %d, out %q; want exit 1 naming the missing role", code, out)
			}
			if dryRun && len(h.api.writes) != 0 {
				t.Fatal("dry run wrote settings")
			}
		})
	}
}
