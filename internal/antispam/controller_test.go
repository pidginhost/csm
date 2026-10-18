package antispam

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
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
