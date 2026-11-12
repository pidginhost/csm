package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
		func(string, string, string) stalwartsetup.API { called = true; return nil },
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
			func(url, user, password string) stalwartsetup.API {
				if user != "admin" || password != setupTestPassword {
					t.Fatalf("login = %q", user)
				}
				return api
			}, sc, in)
	}
	locked := stalwartsetup.Inputs{BlockExpiry: 24 * time.Hour, LockManaged: true, LockedPorts: []int{8080}}

	checks := run(&setupFakeAPI{http: stalwartapi.HTTPSettings{ClientIPSource: "peer"}}, locked)
	if c := stalwartCheckNamed(t, checks, "stalwart failed-login logging"); c.Status != "warn" || c.Fix != "run csm stalwart setup" {
		t.Fatalf("change step = %+v, want warn with the setup fix", c)
	}
	if c := stalwartCheckNamed(t, checks, "stalwart proxy protocol listeners"); c.Status != "ok" {
		t.Fatalf("done step = %+v, want ok", c)
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
	cfg, _ := h.deps.loadConfig()
	got := stalwartSettingsDoctorChecks(context.Background(), h.deps.getenv, h.deps.newAPI, cfg.Stalwart, stalwartsetup.Inputs{})
	for _, c := range got {
		if strings.Contains(c.Message+c.Fix+c.Name, setupTestPassword) {
			t.Fatal("password exposed by doctor")
		}
	}
}
