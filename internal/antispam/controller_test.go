package antispam

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"reflect"
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

func TestParseControllerRejectsNullFields(t *testing.T) {
	for _, field := range []string{"bind_socket", "secure_ip", "password", "enable_password"} {
		for _, value := range []string{`null`, `[null]`, `["localhost:11334",null]`} {
			t.Run(field+"/"+value, func(t *testing.T) {
				fields := `"` + field + `":` + value
				if field != "bind_socket" {
					fields += `,"bind_socket":"localhost:11334"`
				}
				cfg, err := ParseControllerConfig([]byte(workerDump(`{` + fields + `}`)))
				if err == nil || !strings.Contains(err.Error(), field) {
					t.Fatalf("expected error naming %s", field)
				}
				if !reflect.DeepEqual(cfg, ControllerConfig{}) {
					t.Fatal("error returned a partial controller config")
				}
			})
		}
	}
}

func TestParseControllerBindSyntax(t *testing.T) {
	for _, tt := range []struct {
		name, raw, path, host string
		mode                  fs.FileMode
	}{
		{name: "IPv6", raw: "[2001:db8::1]:11334", host: "[2001:db8::1]:11334"},
		{name: "mapped IPv6", raw: "[::ffff:192.0.2.1]:11334", host: "[::ffff:192.0.2.1]:11334"},
		{name: "TLS", raw: "[::1]:11334 ssl", host: "[::1]:11334"},
		{name: "TLS uppercase", raw: "localhost:11334 SSL", host: "localhost:11334"},
		{name: "wildcard v4", raw: "*v4:11334", host: "*v4:11334"},
		{name: "wildcard v6", raw: "*v6:11334", host: "*v6:11334"},
		{name: "default port", raw: "localhost", host: "localhost"},
		{name: "IPv6 default port", raw: "[::1]", host: "[::1]"},
		{name: "priority", raw: "localhost:11334:10", host: "localhost:11334:10"},
		{name: "no mode", raw: "/run/controller.sock", path: "/run/controller.sock"},
		{name: "ownership", raw: "/run/controller.sock owner=_rspamd mode=0600 group=_rspamd", path: "/run/controller.sock", mode: 0o600},
		{name: "commas", raw: "/run/controller.sock,owner=_rspamd,mode=0600,group=_rspamd", path: "/run/controller.sock", mode: 0o600},
		{name: "mixed separators", raw: "/run/controller.sock owner=_rspamd, mode=0660", path: "/run/controller.sock", mode: 0o660},
		{name: "uppercase mode", raw: "/run/controller.sock MODE=0600", path: "/run/controller.sock", mode: 0o600},
		{name: "decimal mode", raw: "/run/controller.sock mode=384", path: "/run/controller.sock", mode: 0o600},
		{name: "no octal prefix", raw: "/run/controller.sock mode=600", path: "/run/controller.sock", mode: 0o130 | fs.ModeSticky},
		{name: "hex mode", raw: "/run/controller.sock mode=0x180", path: "/run/controller.sock", mode: 0o600},
		{name: "special bits", raw: "/run/controller.sock mode=07600", path: "/run/controller.sock", mode: 0o600 | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky},
		{name: "last mode", raw: "/run/controller.sock mode=0600 mode=0666", path: "/run/controller.sock", mode: 0o666},
		{name: "preserve path", raw: "/run/link/../controller.sock mode=0600", path: "/run/link/../controller.sock", mode: 0o600},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bind, err := json.Marshal(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := ParseControllerConfig([]byte(workerDump(`{"bind_socket":` + string(bind) + `}`)))
			if err != nil {
				t.Fatal(err)
			}
			want := ControllerListener{Raw: tt.raw, Unix: tt.path != "", Path: tt.path, HostPort: tt.host, Mode: tt.mode}
			if !cfg.Present || !reflect.DeepEqual(cfg.Listeners, []ControllerListener{want}) {
				t.Fatalf("listeners = %+v, want %+v", cfg.Listeners, want)
			}
		})
	}
}

func TestParseControllerRejectsUnknownBinds(t *testing.T) {
	for _, raw := range []string{
		"systemd:0", "systemd:rspamd.socket", "systemd:0 ssl",
		"localhost:", "localhost:notaport", "localhost:65536",
		"[::1", "[::1]garbage", "[not-an-ip]:11334", "::1:11334",
		"*:11334 garbage", "http://localhost:11334", "./controller.sock", ".",
		"/run/controller.sock\x00ignored", "/run/controller.sock\tmode=0600",
		"/" + strings.Repeat("x", 107), "/run/controller.sock mode=0000",
	} {
		t.Run(fmt.Sprintf("%q", raw), func(t *testing.T) {
			bind, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := ParseControllerConfig([]byte(workerDump(`{"bind_socket":` + string(bind) + `}`)))
			if err == nil || !strings.Contains(err.Error(), "bind_socket") {
				t.Fatal("expected bind_socket error")
			}
			if !reflect.DeepEqual(cfg, ControllerConfig{}) {
				t.Fatal("error returned a partial controller config")
			}
		})
	}
}

func TestParseControllerDumpSize(t *testing.T) {
	// Keep the resource boundary independent of the implementation constant.
	const limit = 16 << 20
	dump := workerDump(`{"bind_socket":"localhost:11334"}`)
	data := []byte(dump + strings.Repeat(" ", limit-len(dump)))
	if cfg, err := ParseControllerConfig(data); err != nil || !cfg.Present {
		t.Fatalf("dump at the limit: present=%v err=%v", cfg.Present, err)
	}
	if cfg, err := ParseControllerConfig(append(data, ' ')); err == nil || !reflect.DeepEqual(cfg, ControllerConfig{}) {
		t.Fatal("oversized dump did not fail without partial config")
	}
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
			t.Fatal("formatted config carries the password")
		}
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatal("JSON config carries the password")
	}
	bad := workerDump(`{"bind_socket":"","password":"` + secret + `"}`)
	if _, err := ParseControllerConfig([]byte(bad)); err == nil {
		t.Fatal("empty bind_socket accepted")
	} else if strings.Contains(err.Error(), secret) {
		t.Fatal("error carries the password")
	}
	if _, err := ParseControllerConfig([]byte(`{"worker":[{"controller":{"password":"` + secret + `",`)); err == nil {
		t.Fatal("truncated dump accepted")
	} else if strings.Contains(err.Error(), secret) {
		t.Fatal("error carries the password")
	}
}

func TestParseControllerRejectsDuplicatesWithoutValues(t *testing.T) {
	const marker = "synthetic-controller-value"
	for name, dump := range map[string]string{
		"root":          `{"worker":{"controller":{"bind_socket":"` + marker + `"}},"worker":[]}`,
		"worker object": `{"worker":{"controller":{"password":"` + marker + `"},"controller":{"bind_socket":"localhost:11334"}}}`,
		"worker list":   `{"worker":[{"controller":{"password":"` + marker + `"},"controller":{"bind_socket":"localhost:11334"}}]}`,
		"escaped field": workerDump(`{"bind_socket":"localhost:11334","password":"` + marker + `","pass\u0077ord":""}`),
		"trust":         workerDump(`{"bind_socket":"localhost:11334","secure_ip":"` + marker + `","secure_ip":[]}`),
		"key":           workerDump(`{"bind_socket":"localhost:11334","` + marker + `":0,"` + marker + `":1}`),
		"password type": workerDump(`{"bind_socket":"localhost:11334","password":{"` + marker + `":1}}`),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := ParseControllerConfig([]byte(dump))
			if err == nil {
				t.Fatal("malformed dump accepted")
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatal("error includes a config value or key")
			}
			if !reflect.DeepEqual(cfg, ControllerConfig{}) {
				t.Fatal("error returned a partial config")
			}
		})
	}
}

func TestParseControllerPasswordPresence(t *testing.T) {
	for _, value := range []string{"", " ", "synthetic-controller-value"} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := ParseControllerConfig([]byte(workerDump(`{"bind_socket":"localhost:11334","password":` + string(encoded) + `,"enable_password":` + string(encoded) + `}`)))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.PasswordSet != (value != "") || cfg.EnablePasswordSet != (value != "") {
			t.Fatal("password presence did not match string emptiness")
		}
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

func hostFacts() ControllerHostFacts {
	return ControllerHostFacts{
		Addrs:        []netip.Prefix{netip.MustParsePrefix("203.0.113.10/32"), netip.MustParsePrefix("2001:db8::10/128")},
		Sockets:      map[string]SocketFacts{},
		GroupMembers: map[int][]string{},
		RspamdUID:    990,
		RspamdGID:    990,
		RspamdUser:   "_rspamd",
	}
}

func tcpController(trust []string, password, enable bool) ControllerConfig {
	return ControllerConfig{
		Present:           true,
		Listeners:         []ControllerListener{{Raw: "localhost:11334", HostPort: "localhost:11334"}},
		TrustEntries:      trust,
		PasswordSet:       password,
		EnablePasswordSet: enable,
	}
}

const unixPath = "/run/rspamd/csm-controller.sock"

func unixController() ControllerConfig {
	return ControllerConfig{Present: true, Listeners: []ControllerListener{{Raw: unixPath + " mode=0600", Unix: true, Path: unixPath, Mode: 0o600}}}
}

func unixSocket(uid, gid int, perm fs.FileMode, parents ...PathFacts) SocketFacts {
	if parents == nil {
		parents = []PathFacts{
			{Path: "/", UID: 0, Mode: fs.ModeDir | 0o755},
			{Path: "/run", UID: 0, Mode: fs.ModeDir | 0o755},
			{Path: "/run/rspamd", UID: 990, GID: 990, Mode: fs.ModeDir | 0o755},
		}
	}
	return SocketFacts{Socket: PathFacts{Path: unixPath, UID: uid, GID: gid, Mode: fs.ModeSocket | perm}, Parents: parents, RspamdUID: 990, PeerUID: -1}
}

func onlyReason(t *testing.T, got []Problem, key, reason string) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("problems = %+v, want exactly one", got)
	}
	p := got[0]
	if p.Code != CodeControllerOpen || p.Severity != Warning || p.Key != key || p.Detail != reason {
		t.Fatalf("problem = %+v, want %s/%s key %q reason %q", p, CodeControllerOpen, "Warning", key, reason)
	}
}

func TestControllerExposureStockLoopbackTrust(t *testing.T) {
	got := ControllerExposure(tcpController([]string{"127.0.0.1", "::1"}, true, false), hostFacts())
	onlyReason(t, got, "localhost:11334", "trusted address reachable by local processes")
}

func TestControllerExposureEmptyTrustStockPassword(t *testing.T) {
	if got := ControllerExposure(tcpController(nil, true, false), hostFacts()); len(got) != 0 {
		t.Fatalf("problems = %+v, want none", got)
	}
}

func TestControllerExposureNoPasswords(t *testing.T) {
	onlyReason(t, ControllerExposure(tcpController(nil, false, false), hostFacts()), "localhost:11334", "no passwords configured")
}

func TestControllerExposureReadOnlyOpen(t *testing.T) {
	onlyReason(t, ControllerExposure(tcpController(nil, false, true), hostFacts()), "localhost:11334", "read-only access without password")
}

func TestControllerExposureMappedLoopback(t *testing.T) {
	onlyReason(t, ControllerExposure(tcpController([]string{"::ffff:127.0.0.1"}, true, true), hostFacts()), "localhost:11334", "trusted address reachable by local processes")
}

func TestControllerExposureWildcardTrust(t *testing.T) {
	for _, entry := range []string{"0.0.0.0/0", "::/0"} {
		onlyReason(t, ControllerExposure(tcpController([]string{entry}, true, true), hostFacts()), "localhost:11334", "trusted address reachable by local processes")
	}
}

func TestControllerExposureHostAddressTrusted(t *testing.T) {
	onlyReason(t, ControllerExposure(tcpController([]string{"203.0.113.10"}, true, true), hostFacts()), "localhost:11334", "trusted address reachable by local processes")
	onlyReason(t, ControllerExposure(tcpController([]string{"2001:db8::/64"}, true, true), hostFacts()), "localhost:11334", "trusted address reachable by local processes")
	if got := ControllerExposure(tcpController([]string{"198.51.100.7"}, true, true), hostFacts()); len(got) != 0 {
		t.Fatalf("remote-only trust entry: problems = %+v, want none", got)
	}
}

func TestControllerExposureUnresolvedTrust(t *testing.T) {
	for _, entry := range []string{"file:///etc/rspamd/trusted.map", "localhost", "/etc/rspamd/trusted.map"} {
		onlyReason(t, ControllerExposure(tcpController([]string{entry}, true, true), hostFacts()), "localhost:11334", "unresolved trust entry")
	}
}

func TestControllerExposurePrivateUnixSocket(t *testing.T) {
	f := hostFacts()
	f.Sockets[unixPath] = unixSocket(990, 990, 0o600)
	if got := ControllerExposure(unixController(), f); len(got) != 0 {
		t.Fatalf("problems = %+v, want none", got)
	}
}

func TestControllerExposureWorldUnixSocket(t *testing.T) {
	f := hostFacts()
	f.Sockets[unixPath] = unixSocket(990, 990, 0o666)
	onlyReason(t, ControllerExposure(unixController(), f), unixPath+" mode=0600", "socket reachable by other users")
}

func TestControllerExposureForeignOwnerUnixSocket(t *testing.T) {
	f := hostFacts()
	f.Sockets[unixPath] = unixSocket(1001, 1001, 0o600)
	onlyReason(t, ControllerExposure(unixController(), f), unixPath+" mode=0600", "socket reachable by other users")
}

func TestControllerExposureACLUnixSocket(t *testing.T) {
	f := hostFacts()
	s := unixSocket(990, 990, 0o600)
	s.Socket.ExtACL = true
	f.Sockets[unixPath] = s
	onlyReason(t, ControllerExposure(unixController(), f), unixPath+" mode=0600", "socket reachable by other users")
}

func TestControllerExposureGroupUnixSocket(t *testing.T) {
	f := hostFacts()
	f.Sockets[unixPath] = unixSocket(990, 965, 0o660)
	f.GroupMembers[965] = []string{"_rspamd", "tenant1"}
	onlyReason(t, ControllerExposure(unixController(), f), unixPath+" mode=0600", "socket reachable by other users")
	f.GroupMembers[965] = []string{"_rspamd", "root"}
	if got := ControllerExposure(unixController(), f); len(got) != 0 {
		t.Fatalf("group of rspamd and root only: problems = %+v, want none", got)
	}
}

func TestControllerExposureReplaceableUnixSocket(t *testing.T) {
	f := hostFacts()
	f.Sockets[unixPath] = unixSocket(990, 990, 0o600,
		PathFacts{Path: "/", UID: 0, Mode: fs.ModeDir | 0o755},
		PathFacts{Path: "/run", UID: 0, Mode: fs.ModeDir | 0o777},
		PathFacts{Path: "/run/rspamd", UID: 990, GID: 990, Mode: fs.ModeDir | 0o755})
	onlyReason(t, ControllerExposure(unixController(), f), unixPath+" mode=0600", "socket parent writable by other users")
}

func TestControllerExposureMissingSocketFacts(t *testing.T) {
	onlyReason(t, ControllerExposure(unixController(), hostFacts()), unixPath+" mode=0600", "socket facts unavailable")
	f := hostFacts()
	f.Sockets[unixPath] = SocketFacts{Err: errors.New("stat failed")}
	onlyReason(t, ControllerExposure(unixController(), f), unixPath+" mode=0600", "socket facts unavailable")
}

func TestControllerExposureAbsentController(t *testing.T) {
	if got := ControllerExposure(ControllerConfig{}, hostFacts()); len(got) != 0 {
		t.Fatalf("problems = %+v, want none", got)
	}
}

func TestControllerExposureOneProblemPerListener(t *testing.T) {
	c := tcpController([]string{"127.0.0.1"}, false, false)
	c.Listeners = append(c.Listeners, ControllerListener{Raw: "*:11334", HostPort: "*:11334"})
	got := ControllerExposure(c, hostFacts())
	if len(got) != 2 || got[0].Key != "localhost:11334" || got[1].Key != "*:11334" {
		t.Fatalf("problems = %+v, want one per listener in order", got)
	}
}

func TestControllerExposureAbsentSocketFile(t *testing.T) {
	f := hostFacts()
	f.Sockets[unixPath] = SocketFacts{Missing: true}
	if got := ControllerExposure(unixController(), f); len(got) != 0 {
		t.Fatalf("no socket file to connect to: problems = %+v, want none", got)
	}
}

func TestControllerExposureNoPasswordsOutranksUnresolved(t *testing.T) {
	onlyReason(t, ControllerExposure(tcpController([]string{"localhost"}, false, false), hostFacts()), "localhost:11334", "no passwords configured")
}

func TestControllerExposureMappedHostAddress(t *testing.T) {
	for _, entry := range []string{"::ffff:203.0.113.10", "::ffff:203.0.113.0/120", "::ffff:0:0/95"} {
		onlyReason(t, ControllerExposure(tcpController([]string{entry}, true, true), hostFacts()), "localhost:11334", "trusted address reachable by local processes")
	}
	if got := ControllerExposure(tcpController([]string{"::ffff:198.51.100.7"}, true, true), hostFacts()); len(got) != 0 {
		t.Fatalf("mapped remote address: problems = %+v, want none", got)
	}
}
