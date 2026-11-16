package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
		func(string) error { return nil },
		config.StalwartConfig{APIURL: "http://127.0.0.1:8080"}, stalwartsetup.Inputs{})
	if len(checks) != 1 || checks[0].Name != "stalwart settings" || checks[0].Status != "ok" {
		t.Fatalf("checks = %+v, want one ok stalwart settings check", checks)
	}
	if !strings.Contains(checks[0].Message, "STALWART_USER") || !strings.Contains(checks[0].Message, "STALWART_PASSWORD") {
		t.Fatalf("message %q does not name both variables", checks[0].Message)
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
	if len(checks) != 1 || checks[0].Status != "warn" || strings.Contains(checks[0].Message, setupTestPassword) {
		t.Fatalf("read error checks = %+v, want one warn without the password", checks)
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
			if len(checks) != 9 || len(h.api.writes) != 0 {
				t.Fatalf("got %d checks, writes %q; want all nine checks and no writes", len(checks), h.api.writes)
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

// doctorChecks runs the settings checks against the harness's fake API.
func (h *setupHarness) doctorChecks() []DoctorCheck {
	cfg, _ := h.deps.loadConfig()
	newAPI := func(url, user, password string) stalwartDoctorAPI {
		h.deps.newAPI(url, user, password)
		return h.api
	}
	return stalwartSettingsDoctorChecks(context.Background(), h.deps.getenv, newAPI, h.deps.checkListener, cfg.Stalwart, stalwartsetup.Inputs{})
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
