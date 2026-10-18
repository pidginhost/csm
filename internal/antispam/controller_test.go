package antispam

import (
	"fmt"
	"strings"
	"testing"
)

// rspamd 4.2.2 `configdump -j` prints the worker section as a list of
// single-key objects, one per worker type. bind_socket is a string, or a
// list when several sockets are bound; secure_ip is a list or a string.
func workerDump(controller string) string {
	return `{"logging":{"type":"file"},"worker":[` +
		`{"normal":{"bind_socket":"/run/rspamd/csm-normal.sock mode=0666","mime":true}},` +
		`{"controller":` + controller + `},` +
		`{"rspamd_proxy":{"bind_socket":"localhost:11332","milter":true}}]}`
}

func TestParseControllerStock(t *testing.T) {
	dump := workerDump(`{"bind_socket":"localhost:11334","count":1,"password":"q1","secure_ip":["127.0.0.1","::1"]}`)
	cfg, err := ParseControllerConfig([]byte(dump))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Present {
		t.Fatal("Present = false, want true")
	}
	if len(cfg.Listeners) != 1 || cfg.Listeners[0].Unix || cfg.Listeners[0].HostPort != "localhost:11334" || cfg.Listeners[0].Raw != "localhost:11334" {
		t.Fatalf("Listeners = %+v, want one TCP listener localhost:11334", cfg.Listeners)
	}
	if strings.Join(cfg.TrustEntries, ",") != "127.0.0.1,::1" {
		t.Fatalf("TrustEntries = %q", cfg.TrustEntries)
	}
	if !cfg.PasswordSet || cfg.EnablePasswordSet {
		t.Fatalf("PasswordSet=%v EnablePasswordSet=%v, want true false", cfg.PasswordSet, cfg.EnablePasswordSet)
	}
}

func TestParseControllerUnixBind(t *testing.T) {
	dump := workerDump(`{"bind_socket":["/run/rspamd/csm-controller.sock mode=0600","localhost:11334"],"secure_ip":[],"password":"x"}`)
	cfg, err := ParseControllerConfig([]byte(dump))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Listeners) != 2 {
		t.Fatalf("Listeners = %+v, want 2", cfg.Listeners)
	}
	u := cfg.Listeners[0]
	if !u.Unix || u.Path != "/run/rspamd/csm-controller.sock" || u.Mode != 0o600 || u.Raw != "/run/rspamd/csm-controller.sock mode=0600" {
		t.Fatalf("Unix listener = %+v", u)
	}
	if cfg.Listeners[1].Unix || cfg.Listeners[1].HostPort != "localhost:11334" {
		t.Fatalf("TCP listener = %+v", cfg.Listeners[1])
	}
}

func TestParseControllerEmptyTrust(t *testing.T) {
	cfg, err := ParseControllerConfig([]byte(workerDump(`{"bind_socket":"localhost:11334","secure_ip":[],"password":"x"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustEntries) != 0 {
		t.Fatalf("TrustEntries = %q, want none", cfg.TrustEntries)
	}
	cfg, err = ParseControllerConfig([]byte(workerDump(`{"bind_socket":"localhost:11334","password":"x"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustEntries) != 0 {
		t.Fatalf("absent secure_ip: TrustEntries = %q, want none", cfg.TrustEntries)
	}
}

func TestParseControllerScalarFields(t *testing.T) {
	cfg, err := ParseControllerConfig([]byte(workerDump(`{"bind_socket":"*:11334","secure_ip":"10.0.0.0/8","enable_password":"y"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Listeners) != 1 || cfg.Listeners[0].HostPort != "*:11334" {
		t.Fatalf("Listeners = %+v", cfg.Listeners)
	}
	if len(cfg.TrustEntries) != 1 || cfg.TrustEntries[0] != "10.0.0.0/8" {
		t.Fatalf("TrustEntries = %q", cfg.TrustEntries)
	}
	if cfg.PasswordSet || !cfg.EnablePasswordSet {
		t.Fatalf("PasswordSet=%v EnablePasswordSet=%v, want false true", cfg.PasswordSet, cfg.EnablePasswordSet)
	}
}

func TestParseControllerObjectShape(t *testing.T) {
	// Older dumps key the worker section by type instead of listing it.
	dump := `{"worker":{"controller":{"bind_socket":"localhost:11334","password":"x"},"normal":{"bind_socket":"localhost:11333"}}}`
	cfg, err := ParseControllerConfig([]byte(dump))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Present || len(cfg.Listeners) != 1 || cfg.Listeners[0].HostPort != "localhost:11334" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestParseControllerAbsent(t *testing.T) {
	dump := `{"worker":[{"normal":{"bind_socket":"localhost:11333"}}]}`
	cfg, err := ParseControllerConfig([]byte(dump))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Present {
		t.Fatalf("Present = true for a dump without a controller: %+v", cfg)
	}
	cfg, err = ParseControllerConfig([]byte(`{"logging":{"type":"file"}}`))
	if err != nil || cfg.Present {
		t.Fatalf("no worker section: cfg=%+v err=%v", cfg, err)
	}
}

func TestParseControllerNeverKeepsPasswords(t *testing.T) {
	const secret = "syntheticSecret12345"
	dump := workerDump(`{"bind_socket":"localhost:11334","password":"` + secret + `","enable_password":"` + secret + `x"}`)
	cfg, err := ParseControllerConfig([]byte(dump))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg)} {
		if strings.Contains(s, secret) {
			t.Fatalf("formatted config carries the password: %s", s)
		}
	}
	bad := workerDump(`{"bind_socket":"","password":"` + secret + `"}`)
	if _, err := ParseControllerConfig([]byte(bad)); err == nil {
		t.Fatal("empty bind_socket accepted")
	} else if strings.Contains(err.Error(), secret) {
		t.Fatalf("error carries the password: %v", err)
	}
	if _, err := ParseControllerConfig([]byte(`{"worker":[{"controller":{"password":"` + secret + `",`)); err == nil {
		t.Fatal("truncated dump accepted")
	} else if strings.Contains(err.Error(), secret) {
		t.Fatalf("error carries the password: %v", err)
	}
}

func TestParseControllerRejectsGarbage(t *testing.T) {
	for name, dump := range map[string]string{
		"not json":         `controller {}`,
		"trailing data":    workerDump(`{"bind_socket":"localhost:11334"}`) + `{}`,
		"duplicate key":    workerDump(`{"bind_socket":"localhost:11334","bind_socket":"*:11334"}`),
		"duplicate worker": `{"worker":[{"controller":{"bind_socket":"a:1"}},{"controller":{"bind_socket":"b:2"}}]}`,
		"relative unix":    workerDump(`{"bind_socket":"run/x.sock mode=0600"}`),
		"bad mode":         workerDump(`{"bind_socket":"/run/x.sock mode=09"}`),
		"password type":    workerDump(`{"bind_socket":"localhost:11334","password":7}`),
		"bind type":        workerDump(`{"bind_socket":7}`),
		"trust type":       workerDump(`{"bind_socket":"localhost:11334","secure_ip":[7]}`),
		"no bind":          workerDump(`{"password":"x"}`),
	} {
		if _, err := ParseControllerConfig([]byte(dump)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
