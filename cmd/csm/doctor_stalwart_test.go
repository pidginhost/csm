package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/stalwartapi"
	"github.com/pidginhost/csm/internal/stalwartlog"
	"github.com/pidginhost/csm/internal/stalwartsetup"
)

var stalwartDoctorNow = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

const (
	doctorAuthSuccess = `2026-11-11T10:00:00Z INFO Authentication successful (auth.success) listenerId = "imaps", localPort = 993, remoteIp = 203.0.113.10, remotePort = 50123, accountName = "user@example.com", accountId = 7`
	doctorAuthFailed  = `2026-11-11T10:01:00Z INFO Authentication failed (auth.failed) listenerId = "smtp", localPort = 587, remoteIp = 203.0.113.11, remotePort = 50124, accountName = "user@example.com", reason = "invalid credentials"`
)

func stalwartDoctorDir(t *testing.T, name string, lines ...string) config.StalwartConfig {
	t.Helper()
	dir := t.TempDir()
	if name != "" {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return config.StalwartConfig{LogDir: dir, LogPrefix: "stalwart.log"}
}

func stalwartCheckNamed(t *testing.T, checks []DoctorCheck, name string) DoctorCheck {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q check in %+v", name, checks)
	return DoctorCheck{}
}

func TestStalwartDoctorNotStalwartHost(t *testing.T) {
	sc := stalwartDoctorDir(t, "")
	for _, mta := range []platform.MTAKind{platform.MTAPostfix, platform.MTAExim, platform.MTAUnknown} {
		if got := stalwartLogDoctorCheck(mta, sc, stalwartDoctorNow); got != nil {
			t.Fatalf("%q host: checks = %+v, want none", mta, got)
		}
	}
}

func TestStalwartDoctorMissingLog(t *testing.T) {
	got := stalwartLogDoctorCheck(platform.MTAStalwart, stalwartDoctorDir(t, ""), stalwartDoctorNow)
	c := stalwartCheckNamed(t, got, "stalwart log")
	if c.Status != "fail" || !strings.Contains(c.Fix, "stalwart.log_dir") {
		t.Fatalf("check = %+v, want fail naming stalwart.log_dir", c)
	}
}

func TestStalwartDoctorStaleLog(t *testing.T) {
	sc := stalwartDoctorDir(t, "stalwart.log.2026-11-01", doctorAuthSuccess)
	c := stalwartCheckNamed(t, stalwartLogDoctorCheck(platform.MTAStalwart, sc, stalwartDoctorNow), "stalwart log")
	if c.Status != "warn" {
		t.Fatalf("check = %+v, want warn for a log ten days old", c)
	}
	sc = stalwartDoctorDir(t, "stalwart.log.2026-11-10", doctorAuthSuccess)
	if c := stalwartCheckNamed(t, stalwartLogDoctorCheck(platform.MTAStalwart, sc, stalwartDoctorNow), "stalwart log"); c.Status != "ok" {
		t.Fatalf("yesterday's file: check = %+v, want ok", c)
	}
}

func TestStalwartDoctorFormat(t *testing.T) {
	sc := stalwartDoctorDir(t, "stalwart.log.2026-11-11", doctorAuthSuccess, doctorAuthFailed)
	if c := stalwartCheckNamed(t, stalwartLogDoctorCheck(platform.MTAStalwart, sc, stalwartDoctorNow), "stalwart log format"); c.Status != "ok" {
		t.Fatalf("parsable lines: check = %+v, want ok", c)
	}
	sc = stalwartDoctorDir(t, "stalwart.log.2026-11-11", doctorAuthSuccess, "garbage")
	if c := stalwartCheckNamed(t, stalwartLogDoctorCheck(platform.MTAStalwart, sc, stalwartDoctorNow), "stalwart log format"); c.Status != "warn" {
		t.Fatalf("some garbage: check = %+v, want warn", c)
	}
	sc = stalwartDoctorDir(t, "stalwart.log.2026-11-11", "garbage", "more garbage")
	if c := stalwartCheckNamed(t, stalwartLogDoctorCheck(platform.MTAStalwart, sc, stalwartDoctorNow), "stalwart log format"); c.Status != "fail" {
		t.Fatalf("all garbage: check = %+v, want fail", c)
	}
}

func TestStalwartDoctorNoFailedLogins(t *testing.T) {
	sc := stalwartDoctorDir(t, "stalwart.log.2026-11-11", doctorAuthSuccess)
	c := stalwartCheckNamed(t, stalwartLogDoctorCheck(platform.MTAStalwart, sc, stalwartDoctorNow), "stalwart failed logins")
	if c.Status != "warn" || !strings.Contains(c.Message, "not detected") || c.Fix != "run csm stalwart setup" {
		t.Fatalf("check = %+v, want warn with the level fix", c)
	}
	sc = stalwartDoctorDir(t, "stalwart.log.2026-11-11", doctorAuthSuccess, doctorAuthFailed)
	if c := stalwartCheckNamed(t, stalwartLogDoctorCheck(platform.MTAStalwart, sc, stalwartDoctorNow), "stalwart failed logins"); c.Status != "ok" {
		t.Fatalf("with an auth.failed line: check = %+v, want ok", c)
	}
}

func TestStalwartDoctorReadsPastOversizedLine(t *testing.T) {
	sc := stalwartDoctorDir(t, "stalwart.log.2026-11-11", strings.Repeat("x", 128*1024), doctorAuthFailed)
	c := stalwartCheckNamed(t, stalwartLogDoctorCheck(platform.MTAStalwart, sc, stalwartDoctorNow), "stalwart failed logins")
	if c.Status != "ok" {
		t.Fatalf("check = %+v, want the failed login after the oversized line to be found", c)
	}
}

func TestStalwartDoctorIgnoresOversizedLineTail(t *testing.T) {
	sc := stalwartDoctorDir(t, "stalwart.log.2026-11-11", strings.Repeat("x", 128*1024)+doctorAuthFailed, doctorAuthSuccess)
	found, err := logHasEvent(filepath.Join(sc.LogDir, "stalwart.log.2026-11-11"), "auth.failed")
	if err != nil || found {
		t.Fatalf("oversized record tail counted as a login: found=%v, err=%v", found, err)
	}
}

const (
	doctorWebmailFailed = `2026-11-11T10:02:00Z INFO Authentication failed (auth.failed) listenerId = "http", localPort = 8080, remoteIp = 198.51.100.7, remotePort = 50125, accountName = "user@example.com", reason = "invalid credentials"`
	doctorWebmailLocal  = `2026-11-11T10:02:00Z INFO Authentication failed (auth.failed) listenerId = "http", localPort = 8080, remoteIp = 127.0.0.1, remotePort = 50125, accountName = "user@example.com", reason = "invalid credentials"`
	doctorBanCDN        = `2026-11-11T10:03:00Z WARN Banned IP address (security.authentication-ban) listenerId = "smtp", localPort = 25, remotePort = 50126, remoteIp = 203.0.113.9, accountName = "user@example.com"`
)

func TestStalwartDoctorSettingsWithoutLogin(t *testing.T) {
	called := false
	checks := stalwartSettingsDoctorChecks(context.Background(), func(string) string { return "" },
		func(string, string, string) stalwartDoctorAPI { called = true; return nil },
		func(string, string) stalwartDoctorAPI { called = true; return nil },
		func(string) error { return nil },
		config.StalwartConfig{APIURL: "http://127.0.0.1:8080", APIKeyFile: filepath.Join(t.TempDir(), "stalwart-api.key")}, stalwartsetup.Inputs{})
	if len(checks) != 2 || checks[0].Name != "stalwart API key" || checks[0].Status != "warn" || checks[1].Name != "stalwart settings" || checks[1].Status != "ok" {
		t.Fatalf("checks = %+v, want the key warning and one ok stalwart settings check", checks)
	}
	if !strings.HasPrefix(checks[1].Message, "Not checked; run csm stalwart setup") {
		t.Fatalf("message %q does not say to run setup", checks[1].Message)
	}
	if !strings.Contains(checks[1].Message, "STALWART_USER") || !strings.Contains(checks[1].Message, "STALWART_PASSWORD") {
		t.Fatalf("message %q does not name both variables", checks[1].Message)
	}
	if called {
		t.Fatal("the API was contacted without a login")
	}
}

func TestStalwartDoctorSettingsFromPlan(t *testing.T) {
	env := map[string]string{"STALWART_USER": "admin", "STALWART_PASSWORD": setupTestPassword}
	sc := config.StalwartConfig{APIURL: "http://127.0.0.1:8080"}
	run := func(api *setupFakeAPI, in stalwartsetup.Inputs) []DoctorCheck {
		return stalwartSettingsDoctorChecks(context.Background(), func(k string) string { return env[k] },
			func(url, user, password string) stalwartDoctorAPI {
				if user != "admin" || password != setupTestPassword {
					t.Fatalf("login = %q", user)
				}
				return api
			}, func(string, string) stalwartDoctorAPI {
				t.Fatal("key client built without a key file")
				return nil
			}, func(string) error { return nil }, sc, in)
	}
	locked := stalwartsetup.Inputs{BlockExpiry: 24 * time.Hour, LockManaged: true, LockedPorts: []int{8080}}

	checks := run(&setupFakeAPI{http: stalwartapi.HTTPSettings{ClientIPSource: "peer"}}, locked)
	if c := stalwartCheckNamed(t, checks, "stalwart failed-login logging"); c.Status != "warn" || c.Fix != "run csm stalwart setup" {
		t.Fatalf("change step = %+v, want warn with the setup fix", c)
	}
	if c := stalwartCheckNamed(t, checks, "stalwart proxy protocol listeners"); c.Status != "ok" {
		t.Fatalf("done step = %+v, want ok", c)
	}
	if c := stalwartCheckNamed(t, checks, "stalwart spam verdict logging"); c.Status != "warn" || c.Fix != "run csm stalwart setup" {
		t.Fatalf("spam verdict logging = %+v, want warn with the setup fix", c)
	}
	if c := stalwartCheckNamed(t, checks, "stalwart spam filter"); c.Status != "warn" || c.Fix != "" {
		t.Fatalf("spam filter off = %+v, want warn with no fix", c)
	}

	checks = run(&setupFakeAPI{http: stalwartapi.HTTPSettings{ClientIPSource: "peer"}}, stalwartsetup.Inputs{BlockExpiry: 24 * time.Hour})
	if c := stalwartCheckNamed(t, checks, "stalwart webmail client addresses"); c.Status != "ok" || !strings.Contains(c.Message, "local_port_locks") {
		t.Fatalf("skipped step = %+v, want ok with the detail", c)
	}

	checks = run(&setupFakeAPI{http: stalwartapi.HTTPSettings{ClientIPSource: "xForwardedFor", ForwardedHops: 1}}, stalwartsetup.Inputs{BlockExpiry: 24 * time.Hour})
	if c := stalwartCheckNamed(t, checks, "stalwart webmail client addresses"); c.Status != "fail" {
		t.Fatalf("unsafe step = %+v, want fail", c)
	}

	api := &setupFakeAPI{readErr: errors.New("dial refused " + setupTestPassword)}
	checks = run(api, locked)
	if len(checks) != 2 || checks[0].Name != "stalwart API key" || checks[1].Name != "stalwart settings" || checks[1].Status != "warn" || strings.Contains(checks[1].Message, setupTestPassword) {
		t.Fatalf("read error checks = %+v, want the key check and one settings warn without the password", checks)
	}
	if checks[1].Fix != "check stalwart.api_url and the admin login" {
		t.Fatalf("read error fix = %q, want the admin login named", checks[1].Fix)
	}
}

func TestStalwartDoctorProxyListenersWarn(t *testing.T) {
	checks := stalwartStepChecks(stalwartsetup.Plan{Steps: []stalwartsetup.Step{{Name: "proxy protocol listeners", State: stalwartsetup.Warn, Detail: "smtp accept"}}})
	if len(checks) != 1 || checks[0].Status != "warn" || checks[0].Name != "stalwart proxy protocol listeners" {
		t.Fatalf("checks = %+v", checks)
	}
}

func TestStalwartDoctorForwardedWithoutLock(t *testing.T) {
	ports, err := stalwartlog.ParsePorts(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c := stalwartForwardedCheck([]string{doctorAuthFailed, doctorWebmailFailed}, ports, nil); c.Status != "warn" || !strings.Contains(c.Message, "198.51.100.7") {
		t.Fatalf("unlocked: %+v, want warn naming the address", c)
	}
	if c := stalwartForwardedCheck([]string{doctorWebmailFailed}, ports, []int{8080}); c.Status != "ok" {
		t.Fatalf("locked: %+v, want ok", c)
	}
	if c := stalwartForwardedCheck([]string{doctorWebmailLocal, doctorAuthFailed}, ports, nil); c.Status != "ok" {
		t.Fatalf("loopback only: %+v, want ok", c)
	}
}

func TestStalwartDoctorCDNBan(t *testing.T) {
	isCDN := func(ip string) bool { return ip == "203.0.113.9" }
	if c := stalwartCDNBanCheck([]string{doctorAuthFailed, doctorBanCDN}, isCDN); c.Status != "warn" || !strings.Contains(c.Message, "203.0.113.9") {
		t.Fatalf("CDN ban: %+v, want warn naming the address", c)
	}
	if c := stalwartCDNBanCheck([]string{doctorAuthFailed}, isCDN); c.Status != "ok" {
		t.Fatalf("no ban: %+v, want ok", c)
	}
}

func TestStalwartDoctorRedactsPlan(t *testing.T) {
	h := newSetupHarness(t)
	h.api.http.ClientIPSource = setupTestPassword
	got := h.doctorChecks()
	for _, c := range got {
		if strings.Contains(c.Message+c.Fix+c.Name, setupTestPassword) {
			t.Fatal("password exposed by doctor")
		}
	}
}

func TestStalwartDoctorSettingsRefusesForeignListener(t *testing.T) {
	env := map[string]string{"STALWART_USER": "admin", "STALWART_PASSWORD": setupTestPassword}
	called := false
	checks := stalwartSettingsDoctorChecks(context.Background(), func(k string) string { return env[k] },
		func(string, string, string) stalwartDoctorAPI { called = true; return nil },
		func(string, string) stalwartDoctorAPI { called = true; return nil },
		func(string) error { return errors.New("port 8080 is held by uid 1001") },
		config.StalwartConfig{APIURL: "http://127.0.0.1:8080"}, stalwartsetup.Inputs{})
	if called || len(checks) != 1 || checks[0].Status != "warn" || !strings.Contains(checks[0].Message, "uid 1001") {
		t.Fatalf("checks = %+v, api contacted %v; want one warn and no login sent", checks, called)
	}
}

func TestStalwartDoctorSpamReadFailureKeepsOtherSteps(t *testing.T) {
	for _, method := range []string{"settings", "stage"} {
		t.Run(method, func(t *testing.T) {
			h := newSetupHarness(t)
			err := errors.New("API error " + setupTestPassword)
			if method == "settings" {
				h.api.spamErr = err
			} else {
				h.api.stageErr = err
			}
			checks := h.doctorChecks()
			for _, c := range checks {
				if strings.Contains(c.Message+c.Fix+c.Name, setupTestPassword) {
					t.Fatal("doctor exposed the password")
				}
			}
			if len(checks) != 11 || len(h.api.writes) != 0 {
				t.Fatalf("got %d checks, writes %q; want all eleven checks and no writes", len(checks), h.api.writes)
			}
			if c := stalwartCheckNamed(t, checks, "stalwart spam filter"); c.Status != "warn" || c.Fix != "" || !strings.Contains(c.Message, "Cannot read") {
				t.Fatalf("spam filter check = %+v", c)
			}
			if c := stalwartCheckNamed(t, checks, "stalwart failed-login logging"); c.Status != "warn" || c.Fix != "run csm stalwart setup" {
				t.Fatalf("failed-login logging check = %+v", c)
			}
		})
	}
}

// doctorChecks runs the settings checks against the harness's fake API. The
// key client answers the session with keyAccount and keyErr.
func (h *setupHarness) doctorChecks() []DoctorCheck {
	cfg, _ := h.deps.loadConfig()
	newAPI := func(url, user, password string) stalwartDoctorAPI {
		h.deps.newAPI(url, user, password)
		return h.api
	}
	newKeyAPI := func(url, key string) stalwartDoctorAPI {
		h.gotURL, h.gotKey = url, key
		h.api.session, h.api.sessionErr = h.keyAccount, h.keyErr
		return h.api
	}
	return stalwartSettingsDoctorChecks(context.Background(), h.deps.getenv, newAPI, newKeyAPI, h.deps.checkListener, cfg.Stalwart, stalwartsetup.Inputs{})
}

const doctorTestKey = "test-key-1"

// newDoctorKeyHarness has CSM's role, account and one key in Stalwart, and a
// key file whose key Stalwart accepts for that account.
func newDoctorKeyHarness(t *testing.T) *setupHarness {
	t.Helper()
	h := newSetupHarness(t)
	h.api.prepare(true)
	h.useKeyFile(t, doctorTestKey)
	h.keyAccount = "a1"
	return h
}

func assertNoDoctorKey(t *testing.T, checks []DoctorCheck) {
	t.Helper()
	for _, c := range checks {
		if strings.Contains(c.Name+c.Message+c.Fix, doctorTestKey) {
			t.Fatalf("check %q exposed the key", c.Name)
		}
	}
}

func TestDoctorUsesKeyBeforeAdminLogin(t *testing.T) {
	h := newDoctorKeyHarness(t)
	checks := h.doctorChecks()
	if h.gotKey != doctorTestKey || h.gotURL != "http://127.0.0.1:8080" {
		t.Fatalf("key client built for %q with the wrong key", h.gotURL)
	}
	if h.gotUser != "" {
		t.Fatal("the admin login was used although the key works")
	}
	if c := stalwartCheckNamed(t, checks, "stalwart API key"); c.Status != "ok" || c.Message != "Stalwart accepts CSM's API key" || c.Fix != "" {
		t.Fatalf("key check = %+v, want ok", c)
	}
	if c := stalwartCheckNamed(t, checks, "stalwart failed-login logging"); c.Status != "warn" || c.Fix != "run csm stalwart setup" {
		t.Fatalf("settings through the key = %+v, want the step read", c)
	}
	assertNoDoctorKey(t, checks)
}

func TestDoctorKeyStates(t *testing.T) {
	for _, tc := range []struct {
		name            string
		mutate          func(t *testing.T, h *setupHarness)
		status, message string
		fix             string
		keySent, admin  bool
	}{
		{"missing", func(t *testing.T, h *setupHarness) {
			h.useKeyFile(t, "")
		}, "warn", "CSM has no API key at ", "run csm stalwart setup", false, true},
		{"loose mode", func(t *testing.T, h *setupHarness) {
			if err := os.Chmod(h.cfg.Stalwart.APIKeyFile, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "fail", "mode 0644 is open to group or others", "", false, true},
		{"refused", func(_ *testing.T, h *setupHarness) {
			h.keyErr = fmt.Errorf("stalwart /.well-known/jmap: bearer %s: %w", doctorTestKey, stalwartapi.ErrUnauthorized)
		}, "fail", "Stalwart refused CSM's API key", "run csm stalwart setup", true, true},
		{"forbidden", func(_ *testing.T, h *setupHarness) {
			h.keyErr = fmt.Errorf("stalwart /.well-known/jmap: bearer %s: %w", doctorTestKey, stalwartapi.ErrForbidden)
		}, "fail", "Stalwart refused CSM's API key", "run csm stalwart setup", true, true},
		{"probe permission", func(_ *testing.T, h *setupHarness) {
			h.keyErr = fmt.Errorf("dial: %w", fs.ErrPermission)
		}, "warn", "Could not check CSM's API key: dial: permission denied", "", true, true},
		{"unreachable", func(_ *testing.T, h *setupHarness) {
			h.keyErr = errors.New("stalwart /.well-known/jmap: dial tcp 127.0.0.1:8080: connection refused, bearer " + doctorTestKey)
		}, "warn", "Could not check CSM's API key: stalwart /.well-known/jmap: dial tcp 127.0.0.1:8080: connection refused", "", true, true},
		{"accepted", func(*testing.T, *setupHarness) {}, "ok", "Stalwart accepts CSM's API key", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newDoctorKeyHarness(t)
			tc.mutate(t, h)
			if tc.keySent {
				// Server text that echoes the key must not reach the output.
				h.api.probe.Tags = []string{"DNSWL_BLOCKED_" + doctorTestKey}
			}
			checks := h.doctorChecks()
			assertNoDoctorKey(t, checks)
			c := stalwartCheckNamed(t, checks, "stalwart API key")
			if c.Status != tc.status || !strings.Contains(c.Message, tc.message) || c.Fix != tc.fix {
				t.Fatalf("key check = %+v, want %s with %q and fix %q", c, tc.status, tc.message, tc.fix)
			}
			if (h.gotKey != "") != tc.keySent || (h.gotUser != "") != tc.admin {
				t.Fatalf("key sent %v, admin login sent %v; want %v, %v", h.gotKey != "", h.gotUser != "", tc.keySent, tc.admin)
			}
			// Either login reads the settings.
			stalwartCheckNamed(t, checks, "stalwart failed-login logging")
		})
	}
}

func TestDoctorReportsRoleDrift(t *testing.T) {
	h := newDoctorKeyHarness(t)
	h.api.role.Enabled = slices.Clone(stalwartsetup.ResponsePermissions[1:])
	checks := h.doctorChecks()
	c := stalwartCheckNamed(t, checks, "stalwart response role")
	if c.Status != "warn" || c.Fix != "run csm stalwart setup" || !strings.Contains(c.Message, "lacks authenticate") {
		t.Fatalf("role check = %+v, want warn naming the missing permission", c)
	}
	if len(h.api.writes) != 0 {
		t.Fatalf("doctor wrote %q", h.api.writes)
	}
}

// A response step setup refuses still ends with a setup run once the operator
// has cleared what it names; settings steps keep their own fixes.
func TestDoctorResponseWarnSaysRunSetup(t *testing.T) {
	h := newDoctorKeyHarness(t)
	h.api.creds = []string{"Password"}
	h.api.spam.Enabled = false
	checks := h.doctorChecks()
	if c := stalwartCheckNamed(t, checks, "stalwart response account"); c.Status != "warn" || c.Fix != "run csm stalwart setup" || !strings.Contains(c.Message, "has a password") {
		t.Fatalf("account check = %+v, want warn with the setup fix", c)
	}
	if c := stalwartCheckNamed(t, checks, "stalwart spam filter"); c.Status != "warn" || c.Fix != "" {
		t.Fatalf("spam filter check = %+v, want warn with no fix", c)
	}
}

func TestDoctorFallsBackToAdminLogin(t *testing.T) {
	h := newSetupHarness(t)
	h.api.prepare(true)
	h.useKeyFile(t, "")
	checks := h.doctorChecks()
	if h.gotKey != "" || h.gotUser != "admin" || h.gotPass != setupTestPassword {
		t.Fatalf("key sent %v, admin login %q; want the admin login only", h.gotKey != "", h.gotUser)
	}
	// Seven settings steps, three response steps, the blocklists and the key.
	if len(checks) != 12 {
		t.Fatalf("got %d checks, want 12: %+v", len(checks), checks)
	}
	if c := checks[0]; c.Name != "stalwart API key" || c.Status != "warn" || c.Fix != "run csm stalwart setup" {
		t.Fatalf("first check = %+v, want the key warning", c)
	}
	if c := stalwartCheckNamed(t, checks, "stalwart response role"); c.Status != "ok" {
		t.Fatalf("role check = %+v, want ok", c)
	}
	if c := stalwartCheckNamed(t, checks, "stalwart response key"); c.Status != "warn" || c.Fix != "run csm stalwart setup" || !strings.Contains(c.Message, "holds no working key") {
		t.Fatalf("key step = %+v, want warn: no working key", c)
	}
	stalwartCheckNamed(t, checks, "stalwart blocklists")
}

func TestDoctorLocalHostShowsTrueResponseSteps(t *testing.T) {
	h := newDoctorKeyHarness(t)
	checks := h.doctorChecks()
	for _, name := range []string{"stalwart response role", "stalwart response account", "stalwart response key"} {
		c := stalwartCheckNamed(t, checks, name)
		if c.Status != "ok" || strings.Contains(c.Message, "not on this host") {
			t.Fatalf("%s = %+v, want ok from Stalwart's state", name, c)
		}
	}
	if c := stalwartCheckNamed(t, checks, "stalwart response key"); !strings.Contains(c.Message, "holds the only key of csm-response@example.org") {
		t.Fatalf("key step = %+v, want the key matched to the account", c)
	}
}

func TestDoctorSendsNoKeyToRemoteAPI(t *testing.T) {
	h := newDoctorKeyHarness(t)
	h.cfg.Stalwart.APIURL = "https://mail.example.org"
	checks := h.doctorChecks()
	if h.gotKey != "" {
		t.Fatal("the key was sent to a remote API address")
	}
	c := stalwartCheckNamed(t, checks, "stalwart API key")
	if c.Status != "ok" || c.Message != "Not checked; Stalwart's API address is not on this host, and CSM's key works only from this host" {
		t.Fatalf("key check = %+v", c)
	}
	if h.gotUser != "admin" {
		t.Fatal("the admin login was not used for a remote API address")
	}
	if c := stalwartCheckNamed(t, checks, "stalwart response key"); c.Status != "ok" || !strings.Contains(c.Message, "not on this host") {
		t.Fatalf("key step = %+v, want skipped as not on this host", c)
	}

	h.env = map[string]string{}
	checks = h.doctorChecks()
	if c := stalwartCheckNamed(t, checks, "stalwart settings"); c.Status != "ok" || !strings.Contains(c.Message, "STALWART_USER") || strings.Contains(c.Message, "run csm stalwart setup") {
		t.Fatalf("settings check = %+v, want the admin login named, not setup", c)
	}
}

func TestDoctorSendsNoKeyWhenListenerCheckFails(t *testing.T) {
	h := newDoctorKeyHarness(t)
	h.deps.checkListener = func(string) error { return errors.New("port 8080 is held by uid 1001") }
	checks := h.doctorChecks()
	if h.gotKey != "" || h.gotUser != "" {
		t.Fatalf("key sent %v, admin login sent %v; want neither", h.gotKey != "", h.gotUser != "")
	}
	if len(checks) != 1 || checks[0].Name != "stalwart settings" || checks[0].Status != "warn" || !strings.Contains(checks[0].Message, "uid 1001") {
		t.Fatalf("checks = %+v, want one warn naming the port's owner", checks)
	}
}

func TestDoctorReportsMissingKeyWhenListenerCheckFails(t *testing.T) {
	h := newDoctorKeyHarness(t)
	h.useKeyFile(t, "")
	h.deps.checkListener = func(string) error { return errors.New("connection refused") }
	checks := h.doctorChecks()
	if len(checks) != 2 {
		t.Fatalf("checks = %+v, want the key warning and the settings warning", checks)
	}
	if c := checks[0]; c.Name != "stalwart API key" || c.Status != "warn" || !strings.Contains(c.Message, "CSM has no API key at ") || c.Fix != "run csm stalwart setup" {
		t.Fatalf("first check = %+v, want the missing key warning", c)
	}
	if c := checks[1]; c.Name != "stalwart settings" || c.Status != "warn" {
		t.Fatalf("second check = %+v, want the settings warning", c)
	}
}

func TestDoctorKeyUnreadableAsNonRootIsWarning(t *testing.T) {
	h := newDoctorKeyHarness(t)
	saved := readStalwartKeyFile
	t.Cleanup(func() { readStalwartKeyFile = saved })
	readStalwartKeyFile = func(path string) (string, error) {
		return "", &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	checks := h.doctorChecks()
	c := stalwartCheckNamed(t, checks, "stalwart API key")
	if c.Status != "warn" || !strings.Contains(c.Message, "only root can read") || c.Fix != "run csm doctor as root" {
		t.Fatalf("key check = %+v, want a warning to run doctor as root", c)
	}
	if h.gotKey != "" {
		t.Fatal("a key was sent")
	}
}

func TestDoctorNeverWrites(t *testing.T) {
	h := newSetupHarness(t)
	h.api.prepare(false)
	path := h.useKeyFile(t, doctorTestKey)
	h.keyAccount = "a9"
	checks := h.doctorChecks()
	for _, name := range []string{"stalwart failed-login logging", "stalwart response role", "stalwart response account", "stalwart response key"} {
		if c := stalwartCheckNamed(t, checks, name); c.Status != "warn" || c.Fix != "run csm stalwart setup" {
			t.Fatalf("%s = %+v, want a change left to setup", name, c)
		}
	}
	if len(h.api.writes) != 0 {
		t.Fatalf("doctor wrote %q", h.api.writes)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != doctorTestKey+"\n" {
		t.Fatalf("doctor changed the key file (%v)", err)
	}
}

func TestStalwartBlocklistCheckWarnsOnBlockedTags(t *testing.T) {
	h := newSetupHarness(t)
	h.api.probe = stalwartapi.SpamProbeResult{Score: 11.2, Result: "spam", Tags: []string{"DNSWL_BLOCKED", "RBL_SENDERSCORE_REPUT_BLOCKED", "RDNS_NONE"}}
	checks := h.doctorChecks()
	c := checks[len(checks)-1]
	if c.Name != "stalwart blocklists" || c.Status != "warn" {
		t.Fatalf("last check = %+v, want a warn stalwart blocklists check after the steps", c)
	}
	if !strings.Contains(c.Message, "DNSWL_BLOCKED, RBL_SENDERSCORE_REPUT_BLOCKED") || strings.Contains(c.Message, "RDNS_NONE") {
		t.Fatalf("message %q, want the two blocked tags only", c.Message)
	}
	if !strings.Contains(c.Fix, "local recursive resolver") || !strings.Contains(c.Fix, "restart Stalwart") {
		t.Fatalf("fix %q, want a local resolver and a restart", c.Fix)
	}
	if len(h.api.probes) != 1 || h.api.probes[0] != stalwartapi.BlocklistProbe {
		t.Fatalf("probes sent = %+v, want the blocklist probe once", h.api.probes)
	}
}

func TestStalwartBlocklistCheckOK(t *testing.T) {
	h := newSetupHarness(t)
	h.api.probe = stalwartapi.SpamProbeResult{Score: 11.2, Result: "spam", Tags: []string{"DMARC_POLICY_REJECT", "RDNS_NONE"}}
	c := stalwartCheckNamed(t, h.doctorChecks(), "stalwart blocklists")
	if c.Status != "ok" || c.Message != "Stalwart's DNS blocklists answer" || c.Fix != "" {
		t.Fatalf("check = %+v, want ok", c)
	}
}

func TestStalwartBlocklistCheckProbeError(t *testing.T) {
	h := newSetupHarness(t)
	h.api.probeErr = errors.New("API error " + setupTestPassword)
	c := stalwartCheckNamed(t, h.doctorChecks(), "stalwart blocklists")
	if c.Status != "warn" || !strings.HasPrefix(c.Message, "Could not test Stalwart's DNS blocklists: ") {
		t.Fatalf("check = %+v, want warn", c)
	}
	if strings.Contains(c.Name+c.Message+c.Fix, setupTestPassword) {
		t.Fatal("blocklist check exposed the password")
	}
}

func TestStalwartBlocklistCheckSkippedWhenFilterOff(t *testing.T) {
	h := newSetupHarness(t)
	h.api.spam.Enabled = false
	for _, c := range h.doctorChecks() {
		if c.Name == "stalwart blocklists" {
			t.Fatalf("filter off: got %+v, want no blocklist check", c)
		}
	}
	if len(h.api.probes) != 0 {
		t.Fatalf("filter off: probes sent = %d, want none", len(h.api.probes))
	}

	h = newSetupHarness(t)
	h.env = map[string]string{}
	h.doctorChecks()
	if len(h.api.probes) != 0 {
		t.Fatalf("no login: probes sent = %d, want none", len(h.api.probes))
	}
}

const (
	doctorTrainStarted = `2026-11-11T10:00:00Z INFO Spam classifier training started (spam.train-started) `
	doctorNotReady     = `2026-11-11T10:00:10Z INFO Spam classifier model not ready (spam.model-not-ready) reason = "Not enough samples for training", details = [19, 3], limit = [100, 100], elapsed = 8ms`
	doctorNotReadyOld  = `2026-11-11T00:00:10Z INFO Spam classifier model not ready (spam.model-not-ready) reason = "Not enough samples for training", details = [7, 1], limit = [100, 100], elapsed = 8ms`
	doctorNotReadyOne  = `2026-11-11T10:00:10Z INFO Spam classifier model not ready (spam.model-not-ready) reason = "Not enough samples for training", details = [19], limit = [100, 100], elapsed = 8ms`
)

func TestStalwartClassifierCheck(t *testing.T) {
	const want = "Stalwart's spam classifier is still learning: 19 of 100 ham and 3 of 100 spam samples"
	cases := []struct {
		name  string
		lines []string
		found bool
	}{
		{"one line", []string{doctorTrainStarted, doctorNotReady}, true},
		{"later line wins", []string{doctorTrainStarted, doctorNotReadyOld, doctorTrainStarted, doctorNotReady}, true},
		{"training started after", []string{doctorTrainStarted, doctorNotReady, doctorTrainStarted}, false},
		{"no event", []string{doctorAuthSuccess}, false},
		{"one count", []string{doctorTrainStarted, doctorNotReadyOne}, false},
		{"oversized tail is not a record", []string{strings.Repeat("x", 128*1024) + doctorNotReady}, false},
		{"oversized training tail does not clear status", []string{doctorNotReady, strings.Repeat("x", 128*1024) + doctorTrainStarted}, true},
		{"event name in another event's value", []string{doctorNotReady, doctorAuthSuccess + `, reason = "(spam.train-started) ignored"`}, true},
		{"malformed unrelated record cannot clear status", []string{doctorNotReady, doctorAuthSuccess + `, reason = "(spam.train-started) broken`}, true},
		{"malformed training body clears status", []string{doctorNotReady, doctorTrainStarted + `details = [`}, false},
		{"after an oversized line", []string{strings.Repeat("x", 128*1024), doctorNotReady}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := stalwartDoctorDir(t, "stalwart.log.2026-11-11", tc.lines...)
			var got []DoctorCheck
			for _, c := range stalwartLogDoctorCheck(platform.MTAStalwart, sc, stalwartDoctorNow) {
				if c.Name == "stalwart spam classifier" {
					got = append(got, c)
				}
			}
			if !tc.found {
				if len(got) != 0 {
					t.Fatalf("checks = %+v, want no classifier check", got)
				}
				return
			}
			if len(got) != 1 || got[0].Status != "ok" || got[0].Message != want || got[0].Fix != "" {
				t.Fatalf("checks = %+v, want one ok %q", got, want)
			}
		})
	}
}

func TestStalwartBlocklistOutputSafety(t *testing.T) {
	for _, tc := range []struct {
		name string
		tags []string
	}{
		{"controls", []string{"DNSWL_BLOCKED\x1b[2J\r\n\t\x00\u0085\u202e"}},
		{"long tag", []string{strings.Repeat("x", 8192) + "_BLOCKED"}},
		{"many tags", strings.Fields(strings.Repeat("DNSWL_BLOCKED ", 10000))},
		{"blocked after many ordinary tags", append(strings.Fields(strings.Repeat("RDNS_NONE ", 10000)), "DNSWL_BLOCKED")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSetupHarness(t)
			h.api.probe = stalwartapi.SpamProbeResult{Tags: tc.tags, Result: "verdict-must-not-appear", Score: 12345.6789}
			c := stalwartCheckNamed(t, h.doctorChecks(), "stalwart blocklists")
			if c.Status != "warn" {
				t.Fatalf("status = %s, want warn", c.Status)
			}
			if len(c.Message) > 1024 {
				t.Errorf("message has %d bytes, want at most 1024", len(c.Message))
			}
			for _, r := range c.Name + c.Message + c.Fix {
				if r < 32 || r > 126 {
					t.Fatal("non-ASCII or control character in terminal output")
				}
			}
			if strings.Contains(c.Message, "verdict-must-not-appear") || strings.Contains(c.Message, "12345.6789") {
				t.Fatal("probe verdict or score printed")
			}
			if tc.name == "many tags" || tc.name == "long tag" {
				if !strings.Contains(c.Message, "...") {
					t.Fatal("truncated tags need a visible omission marker")
				}
			}
		})
	}
}

func TestStalwartClassifierMalformedLatest(t *testing.T) {
	for _, fields := range []string{
		"details = [19, 3", "details = [19,, 3], limit = [100, 100]",
		"details = [19, 3], limit = [100, 100", "details = [19, -3], limit = [100, 100]",
		"details = [19, 3], limit = [100]", "details = [19, 3], limit = [100, nope]",
		"details = [19, 18446744073709551616], limit = [100, 100]",
	} {
		t.Run(fields, func(t *testing.T) {
			line := "2026-11-11T10:01:00Z INFO Model not ready (spam.model-not-ready) " + fields
			sc := stalwartDoctorDir(t, "stalwart.log.2026-11-11", doctorNotReady, line)
			if _, ok := stalwartClassifierCheck(filepath.Join(sc.LogDir, "stalwart.log.2026-11-11")); ok {
				t.Fatal("malformed newest record retained an older classifier status")
			}
		})
	}
}

func TestStalwartBlocklistProbeGates(t *testing.T) {
	for _, mode := range []string{"plan error", "settings error", "stage error", "stage off", "missing user", "missing password", "foreign listener"} {
		t.Run(mode, func(t *testing.T) {
			h := newSetupHarness(t)
			switch mode {
			case "plan error":
				h.api.readErr = errors.New("unavailable")
			case "settings error":
				h.api.spamErr = errors.New("unavailable")
			case "stage error":
				h.api.stageErr = errors.New("unavailable")
			case "stage off":
				h.api.stageOff = true
			case "missing user":
				delete(h.env, "STALWART_USER")
			case "missing password":
				delete(h.env, "STALWART_PASSWORD")
			case "foreign listener":
				h.deps.checkListener = func(string) error { return errors.New("foreign listener") }
			}
			for _, c := range h.doctorChecks() {
				if c.Name == "stalwart blocklists" {
					t.Fatal("unexpected blocklist check")
				}
			}
			if len(h.api.probes) != 0 || len(h.api.writes) != 0 {
				t.Fatal("unexpected probe or settings write")
			}
		})
	}
}

func BenchmarkStalwartLogHasEvent(b *testing.B) {
	for _, lines := range []int{1000, 10000} {
		b.Run(fmt.Sprint(lines), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "stalwart.log")
			data := []byte(strings.Repeat(doctorAuthSuccess+"\n", lines))
			if err := os.WriteFile(path, data, 0o600); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if found, err := logHasEvent(path, "auth.failed"); err != nil || found {
					b.Fatalf("found=%v, err=%v", found, err)
				}
			}
		})
	}
}

func TestStalwartBlocklistRedactsBeforeFormatting(t *testing.T) {
	for _, probeError := range []bool{false, true} {
		t.Run(fmt.Sprint(probeError), func(t *testing.T) {
			h := newSetupHarness(t)
			password := setupTestPassword + "\n\x1b"
			h.env["STALWART_PASSWORD"] = password
			if probeError {
				h.api.probeErr = errors.New("API error " + password + "\x1b[2J")
			} else {
				h.api.probe.Tags = []string{"DNSWL_BLOCKED_" + password}
			}
			checks := h.doctorChecks()
			for _, c := range checks {
				text := c.Name + c.Message + c.Fix
				if strings.Contains(text, setupTestPassword) || strings.Contains(text, strconv.QuoteToASCII(password)) {
					t.Fatal("password exposed")
				}
			}
			c := stalwartCheckNamed(t, checks, "stalwart blocklists")
			if c.Status != "warn" || !strings.Contains(c.Message, "[redacted]") {
				t.Fatal("missing redacted warning")
			}
			for _, r := range c.Message {
				if r < 32 || r > 126 {
					t.Fatal("terminal control in warning")
				}
			}
		})
	}
}

func TestStalwartClassifierNewestFile(t *testing.T) {
	sc := stalwartDoctorDir(t, "stalwart.log.2026-11-10", doctorNotReady)
	latest := filepath.Join(sc.LogDir, "stalwart.log.2026-11-11")
	if err := os.WriteFile(latest, []byte(doctorAuthSuccess), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range stalwartLogDoctorCheck(platform.MTAStalwart, sc, stalwartDoctorNow) {
		if c.Name == "stalwart spam classifier" {
			t.Fatal("classifier status came from an older log")
		}
	}
	line := strings.Replace(doctorNotReady, "[100, 100]", "[100, 200]", 1)
	if err := os.WriteFile(latest, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	c := stalwartCheckNamed(t, stalwartLogDoctorCheck(platform.MTAStalwart, sc, stalwartDoctorNow), "stalwart spam classifier")
	if c.Status != "ok" || c.Message != "Stalwart's spam classifier is still learning: 19 of 100 ham and 3 of 200 spam samples" {
		t.Fatalf("unexpected classifier status: %+v", c)
	}
}

func TestStalwartMalformedLoginIsNotAnEvent(t *testing.T) {
	sc := stalwartDoctorDir(t, "stalwart.log.2026-11-11", doctorAuthFailed+`, details = [1, 2`)
	if found, err := logHasEvent(filepath.Join(sc.LogDir, "stalwart.log.2026-11-11"), "auth.failed"); err != nil || found {
		t.Fatalf("found=%v, err=%v", found, err)
	}
}

func TestDoctorMissingKeyNotReportedForFailedRemoteListener(t *testing.T) {
	h := newDoctorKeyHarness(t)
	h.useKeyFile(t, "")
	h.cfg.Stalwart.APIURL = "https://mail.example.org"
	h.deps.checkListener = func(string) error { return errors.New("connection refused") }
	checks := h.doctorChecks()
	if len(checks) != 1 || checks[0].Name != "stalwart settings" || checks[0].Status != "warn" {
		t.Fatalf("checks = %+v; want only the remote listener warning", checks)
	}
	if h.gotKey != "" || h.gotUser != "" {
		t.Fatal("a failed listener check sent a login")
	}
}
