package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
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
	if c.Status != "warn" || !strings.Contains(c.Message, "not detected") || !strings.Contains(c.Fix, "auth.failed event to the info level") {
		t.Fatalf("check = %+v, want warn with the level fix", c)
	}
	sc = stalwartDoctorDir(t, "stalwart.log.2026-11-11", doctorAuthSuccess, doctorAuthFailed)
	if c := stalwartCheckNamed(t, stalwartLogDoctorCheck(platform.MTAStalwart, sc, stalwartDoctorNow), "stalwart failed logins"); c.Status != "ok" {
		t.Fatalf("with an auth.failed line: check = %+v, want ok", c)
	}
}
