package config

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidationResultString(t *testing.T) {
	r := ValidationResult{Level: "error", Field: "hostname", Message: "not set"}
	got := r.String()
	want := "[ERROR] hostname: not set"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestValidationResultStringUppercasesMixedCaseLevel(t *testing.T) {
	r := ValidationResult{Level: "Warn", Field: "alerts", Message: "no recipients"}
	if got := r.String(); got != "[WARN] alerts: no recipients" {
		t.Fatalf("String() = %q", got)
	}
}

func TestSaveRoundTripsConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csm.yaml")
	cfg := &Config{
		ConfigFile: path,
		Hostname:   "web01.example.com",
	}
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"ops@example.com"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = "smtp.example.com:587"

	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("mode = %o, want 0600", info.Mode().Perm())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "web01.example.com") {
		t.Errorf("saved config missing hostname: %s", s)
	}
	if !strings.Contains(s, "ops@example.com") {
		t.Errorf("saved config missing alert recipient: %s", s)
	}
}

func TestSaveFailsOnUnwritablePath(t *testing.T) {
	cfg := &Config{ConfigFile: "/nonexistent/dir/csm.yaml", Hostname: "h"}
	if err := Save(cfg); err == nil {
		t.Fatal("Save to nonexistent dir should fail")
	}
}

func TestEmailAVScanTimeoutDurationDefault(t *testing.T) {
	c := &EmailAVConfig{}
	if got := c.ScanTimeoutDuration(); got != 30*time.Second {
		t.Errorf("empty ScanTimeout -> %v, want 30s", got)
	}
}

func TestEmailAVScanTimeoutDurationExplicit(t *testing.T) {
	c := &EmailAVConfig{ScanTimeout: "45s"}
	if got := c.ScanTimeoutDuration(); got != 45*time.Second {
		t.Errorf("45s -> %v, want 45s", got)
	}
}

func TestEmailAVScanTimeoutDurationInvalid(t *testing.T) {
	c := &EmailAVConfig{ScanTimeout: "not a duration"}
	if got := c.ScanTimeoutDuration(); got != 30*time.Second {
		t.Errorf("invalid -> %v, want 30s fallback", got)
	}
}

func TestProbeSMTPReachable(t *testing.T) {
	// Real TCP listener — any protocol, probe only dials.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	results := probeSMTP(ln.Addr().String())
	if len(results) != 1 || results[0].Level != "ok" {
		t.Fatalf("probeSMTP reachable = %+v, want single ok result", results)
	}
	if !strings.Contains(results[0].Message, "connected to") {
		t.Errorf("message = %q, want connected to message", results[0].Message)
	}
}

func TestProbeSMTPUnreachable(t *testing.T) {
	// Reserve an ephemeral port then immediately release it to get a
	// "nothing listening here" address.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	results := probeSMTP(addr)
	if len(results) != 1 || results[0].Level != "error" {
		t.Fatalf("probeSMTP unreachable = %+v, want single error", results)
	}
}

func TestProbeClamdReachable(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "clamd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	results := probeClamd(sock)
	if len(results) != 1 || results[0].Level != "ok" {
		t.Fatalf("probeClamd reachable = %+v, want ok", results)
	}
}

func TestProbeClamdUnreachable(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nonexistent.sock")

	results := probeClamd(sock)
	if len(results) != 1 || results[0].Level != "error" {
		t.Fatalf("probeClamd missing socket = %+v, want error", results)
	}
}

func TestProbeWebhookOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// probeWebhook uses HEAD; return a non-2xx to prove any status is ok.
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	results := probeWebhook(srv.URL)
	if len(results) != 1 || results[0].Level != "ok" {
		t.Fatalf("probeWebhook 401 = %+v, want ok (any HTTP status means reachable)", results)
	}
	if !strings.Contains(results[0].Message, "HTTP 401") {
		t.Errorf("message = %q, want it to include the HTTP status", results[0].Message)
	}
}

func TestProbeWebhookUnreachable(t *testing.T) {
	// Use a non-routable address that fails fast. 127.0.0.1:1 is
	// guaranteed to refuse on most systems; fallback to a port we just
	// released if that doesn't error out.
	results := probeWebhook("http://127.0.0.1:1/")
	if len(results) != 1 || results[0].Level != "error" {
		t.Fatalf("probeWebhook :1 = %+v, want error", results)
	}
}
