package hostfacts

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func controllerDump(bind string) string {
	return `{"logging":{"type":"console"},"worker":[{"normal":{"bind_socket":"localhost:11333"}},` +
		`{"controller":{"bind_socket":["` + bind + ` mode=0600","localhost:11334"],"secure_ip":[],"password":"synthetic-secret-1"}}]}`
}

func listenUnix(t *testing.T, path string) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("close Unix listener: %v", err)
		}
	})
}

func TestCollectControllerFromFullDump(t *testing.T) {
	d := t.TempDir()
	sock := filepath.Join(d, "ctl.sock")
	listenUnix(t, sock)
	run := &fakeRun{results: map[string]antispam.CommandResult{"rspamadm configdump -j": {Stdout: controllerDump(sock)}}}
	c := testCollector(d, run)
	c.interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("203.0.113.10"), Mask: net.CIDRMask(24, 32)}}, nil
	}
	f := c.collect(context.Background(), antispam.DefaultSocket)
	if f.ControllerErr != nil {
		t.Fatalf("ControllerErr = %v", f.ControllerErr)
	}
	if !f.Controller.Present || len(f.Controller.Listeners) != 2 || f.Controller.Listeners[0].Path != sock {
		t.Fatalf("Controller = %+v", f.Controller)
	}
	s, ok := f.ControllerHost.Sockets[sock]
	if !ok || s.Err != nil || s.Missing || s.Socket.Mode.Type() != fs.ModeSocket {
		t.Fatalf("socket facts = %+v (present %v)", s, ok)
	}
	if len(s.Parents) == 0 || s.Parents[len(s.Parents)-1].Path != d {
		t.Fatalf("parents = %+v, want the walk to end at %s", s.Parents, d)
	}
	if !slices.Contains(f.ControllerHost.Addrs, netip.MustParsePrefix("203.0.113.10/32")) {
		t.Fatalf("Addrs = %v, want the host address as a /32", f.ControllerHost.Addrs)
	}
}

func TestCollectControllerGroupMembers(t *testing.T) {
	d := t.TempDir()
	sock := filepath.Join(d, "ctl.sock")
	listenUnix(t, sock)
	gid := os.Getgid()
	run := &fakeRun{results: map[string]antispam.CommandResult{"rspamadm configdump -j": {Stdout: controllerDump(sock)}}}
	c := testCollector(d, run)
	c.readGroup = func() ([]byte, error) {
		return []byte(fmt.Sprintf("root:x:0:\nshared:x:%d:_rspamd,redis\nalias:x:%d:tenant2\n", gid, gid)), nil
	}
	c.readPasswd = func() ([]byte, error) {
		return []byte(fmt.Sprintf("root:x:0:0::/root:/bin/bash\ntenant1:x:1001:%d::/home/tenant1:/bin/bash\n", gid)), nil
	}
	f := c.collect(context.Background(), antispam.DefaultSocket)
	got := f.ControllerHost.GroupMembers[gid]
	for _, want := range []string{"_rspamd", "redis", "tenant1", "tenant2"} {
		if !slices.Contains(got, want) {
			t.Fatalf("GroupMembers[%d] = %v, want %s (group list or primary group)", gid, got, want)
		}
	}
}

func TestCollectControllerDumpError(t *testing.T) {
	d := t.TempDir()
	c := testCollector(d, &fakeRun{results: map[string]antispam.CommandResult{"rspamadm configdump -j": {Err: errors.New("exit 1")}}})
	f := c.collect(context.Background(), antispam.DefaultSocket)
	if f.ControllerErr == nil || f.Controller.Present {
		t.Fatalf("Controller = %+v, ControllerErr = %v; want an error and nothing present", f.Controller, f.ControllerErr)
	}
}

func TestCollectControllerServiceIdentity(t *testing.T) {
	d := t.TempDir()
	run := &fakeRun{results: map[string]antispam.CommandResult{
		"rspamadm configdump -j": {Stdout: controllerDump(filepath.Join(d, "absent.sock"))},
		"systemctl " + strings.Join(antispam.UnitShowArgs(antispam.RspamdUnit), " "): {Stdout: "LoadState=loaded\nUser=_rspamd\nGroup=\n"},
	}}
	f := testCollector(d, run).collect(context.Background(), antispam.DefaultSocket)
	h := f.ControllerHost
	if h.RspamdUID != 979 || h.RspamdGID != 974 || h.RspamdUser != "_rspamd" {
		t.Fatalf("identity = uid %d gid %d user %q, want 979 974 _rspamd", h.RspamdUID, h.RspamdGID, h.RspamdUser)
	}
	if s := h.Sockets[filepath.Join(d, "absent.sock")]; !s.Missing {
		t.Fatalf("absent socket facts = %+v, want Missing", s)
	}
}

func TestControllerInterfaceErrorIsUnknown(t *testing.T) {
	c := testCollector(t.TempDir(), &fakeRun{})
	c.interfaceAddrs = func() ([]net.Addr, error) {
		return nil, errors.New("private diagnostic")
	}
	f := antispam.HostFacts{RspamdConfig: antispam.CommandResult{Stdout: controllerDump("/missing.sock")}}
	c.controllerFacts(&f)
	if f.ControllerErr == nil || strings.Contains(f.ControllerErr.Error(), "private diagnostic") {
		t.Fatal("interface failure must produce a value-free controller error")
	}
	for _, dump := range []string{`{}`, `{"worker":{"controller":{"bind_socket":"/missing.sock"}}}`} {
		f = antispam.HostFacts{RspamdConfig: antispam.CommandResult{Stdout: dump}}
		c.controllerFacts(&f)
		if f.ControllerErr != nil {
			t.Fatal("interface failure affected a controller without TCP listeners")
		}
	}
}

func TestControllerSocketLookupMatchesKernel(t *testing.T) {
	d := t.TempDir()
	mkdir(t, filepath.Join(d, "target", "child"))
	sock := filepath.Join(d, "target", "ctl.sock")
	listenUnix(t, sock)
	if err := os.Symlink("target/child", filepath.Join(d, "link")); err != nil {
		t.Fatal(err)
	}
	// Cleaning before lookup would remove link/.. and inspect a different path.
	bind := d + "/link/../ctl.sock"
	f := antispam.HostFacts{RspamdConfig: antispam.CommandResult{Stdout: controllerDump(bind)}}
	c := testCollector(d, &fakeRun{})
	c.controllerFacts(&f)
	if f.ControllerErr != nil || len(f.Controller.Listeners) != 2 {
		t.Fatal("controller configuration could not be read")
	}
	s := f.ControllerHost.Sockets[f.Controller.Listeners[0].Path]
	if s.Err != nil || s.Missing || s.Socket.Path != sock || s.Socket.Mode.Type() != fs.ModeSocket {
		t.Fatalf("socket facts = %+v, want the socket reached by the kernel", s)
	}
	paths := make([]string, 0, len(s.Parents))
	for _, p := range s.Parents {
		paths = append(paths, p.Path)
	}
	for _, p := range []string{d, filepath.Join(d, "target"), filepath.Join(d, "target", "child")} {
		if !slices.Contains(paths, p) {
			t.Errorf("lookup omitted parent %s", p)
		}
	}
	if s.PeerUID != -1 || s.PingErr != nil {
		t.Fatal("controller socket was probed")
	}
}

func TestControllerSocketMustBeSocket(t *testing.T) {
	d := t.TempDir()
	file := filepath.Join(d, "regular")
	write(t, file, "")
	for _, path := range []string{file, d} {
		if s := unixSocketFacts(path); s.Err == nil || s.Missing {
			t.Fatalf("%s: non-socket must have an error", path)
		}
	}
}

func TestControllerMalformedAccountsStayUnknown(t *testing.T) {
	const group = "service:x:974:_rspamd\n"
	const passwd = "_rspamd:x:979:974::/:/bin/false\n"
	for name, files := range map[string][2]string{
		"short group":       {group + "alias:x:974\n", passwd},
		"extra group field": {group + "alias:x:974:_rspamd:tenant\n", passwd},
		"invalid group gid": {group + "alias:x:invalid:tenant\n", passwd},
		"empty member":      {group + "alias:x:974:,\n", passwd},
		"short passwd":      {group, passwd + "tenant:x:1001\n"},
		"invalid user gid":  {group, passwd + "tenant:x:1001:invalid::/:/bin/false\n"},
		"invalid user uid":  {group, passwd + "tenant:x:invalid:974::/:/bin/false\n"},
		"empty username":    {group, ":x:1001:974::/:/bin/false\n"},
		"nul in member":     {group + "alias:x:974:tenant\x00\n", passwd},
	} {
		t.Run(name, func(t *testing.T) {
			c := testCollector(t.TempDir(), &fakeRun{})
			c.readGroup = func() ([]byte, error) { return []byte(files[0]), nil }
			c.readPasswd = func() ([]byte, error) { return []byte(files[1]), nil }
			if got := c.groupMembers(map[int]bool{974: true}); len(got) != 0 {
				t.Fatal("malformed account data was treated as a complete membership list")
			}
		})
	}
}

func TestControllerAccountReadErrorsStayUnknown(t *testing.T) {
	for _, failed := range []string{"group", "passwd"} {
		t.Run(failed, func(t *testing.T) {
			c := testCollector(t.TempDir(), &fakeRun{})
			c.readGroup = func() ([]byte, error) {
				if failed == "group" {
					return []byte("service:x:974:_rspamd\n"), errors.New("unreadable")
				}
				return []byte("service:x:974:_rspamd\n"), nil
			}
			c.readPasswd = func() ([]byte, error) {
				if failed == "passwd" {
					return nil, errors.New("unreadable")
				}
				return nil, nil
			}
			if got := c.groupMembers(map[int]bool{974: true}); len(got) != 0 {
				t.Fatal("partial account read was trusted")
			}
		})
	}
}

func TestControllerLargeAccountFiles(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "accounts")
	for _, size := range []int{maxAccountFileBytes, maxAccountFileBytes + 1} {
		write(t, p, strings.Repeat("\n", size))
		got, err := readAccountFile(p)
		if size == maxAccountFileBytes {
			if err != nil || len(got) != size {
				t.Fatalf("read at limit: length=%d err=%v", len(got), err)
			}
		} else if err == nil || len(got) != 0 {
			t.Fatal("oversized account file returned partial data")
		}
	}
	// A long valid line must not silently drop the final supplementary member.
	c := testCollector(d, &fakeRun{})
	c.readGroup = func() ([]byte, error) {
		return []byte("service:x:974:" + strings.Repeat("_rspamd,", 10000) + "tenant\n"), nil
	}
	c.readPasswd = func() ([]byte, error) { return []byte("primary:x:1001:974::/:/bin/false\n"), nil }
	got := c.groupMembers(map[int]bool{974: true})[974]
	if !slices.Contains(got, "tenant") || !slices.Contains(got, "primary") {
		t.Fatal("large account line lost a supplementary or primary member")
	}
}

func TestControllerAddressesAreHostPrefixes(t *testing.T) {
	c := testCollector(t.TempDir(), &fakeRun{})
	c.interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("203.0.113.10"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("::ffff:192.0.2.10"), Mask: net.CIDRMask(120, 128)},
			&net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}
	f := antispam.HostFacts{RspamdConfig: antispam.CommandResult{Stdout: controllerDump("/missing.sock")}}
	c.controllerFacts(&f)
	want := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.10/32"),
		netip.MustParsePrefix("192.0.2.10/32"),
		netip.MustParsePrefix("2001:db8::10/128"),
	}
	if f.ControllerErr != nil || !slices.Equal(f.ControllerHost.Addrs, want) {
		t.Fatalf("host prefixes = %v, want %v", f.ControllerHost.Addrs, want)
	}
}

func TestControllerNumericServiceUser(t *testing.T) {
	c := testCollector(t.TempDir(), &fakeRun{})
	c.userName = func(uid string) (string, error) {
		if uid != "979" {
			t.Fatalf("lookup uid %q, want 979", uid)
		}
		return "_rspamd", nil
	}
	f := antispam.HostFacts{
		RspamdConfig:  antispam.CommandResult{Stdout: controllerDump("/missing.sock")},
		RspamdService: antispam.CommandResult{Stdout: "LoadState=loaded\nUser=979\n"},
		Socket:        antispam.SocketFacts{RspamdUID: 979},
		RspamdGID:     974,
	}
	c.controllerFacts(&f)
	if f.ControllerHost.RspamdUser != "_rspamd" {
		t.Fatalf("service user = %q, want account name", f.ControllerHost.RspamdUser)
	}
	c.userName = func(string) (string, error) { return "", errors.New("lookup failed") }
	c.controllerFacts(&f)
	if f.ControllerHost.RspamdUser != "" {
		t.Fatal("unresolved numeric service user must stay unknown")
	}
}

func TestControllerUnknownServiceIdentity(t *testing.T) {
	for name, result := range map[string]antispam.CommandResult{
		"no systemd": {Err: errors.New("systemctl unavailable")},
		"not loaded": {Stdout: "LoadState=not-found\nUser=_rspamd\n"},
		"no user":    {Stdout: "LoadState=loaded\nUser=\n"},
		"root user":  {Stdout: "LoadState=loaded\nUser=0\n"},
	} {
		t.Run(name, func(t *testing.T) {
			run := &fakeRun{results: map[string]antispam.CommandResult{
				"rspamadm configdump -j": {Stdout: controllerDump("/missing.sock")},
				"systemctl " + strings.Join(antispam.UnitShowArgs(antispam.RspamdUnit), " "): result,
			}}
			f := testCollector(t.TempDir(), run).collect(context.Background(), antispam.DefaultSocket)
			h := f.ControllerHost
			if f.ControllerErr != nil || h.RspamdUID != -1 || h.RspamdGID != -1 || h.RspamdUser != "" {
				t.Fatalf("unknown service: uid=%d gid=%d user=%q err=%v", h.RspamdUID, h.RspamdGID, h.RspamdUser, f.ControllerErr)
			}
		})
	}
}

func TestControllerFactsDoNotKeepPasswords(t *testing.T) {
	const marker = "synthetic-password-marker"
	for i, dump := range []string{
		`{"worker":{"controller":{"bind_socket":"localhost:11334","password":"` + marker + `","enable_password":"` + marker + `"}}}`,
		`{"worker":{"controller":{"bind_socket":"localhost:11334","password":{"` + marker + `":true}}}}`,
		`{"worker":{"controller":{"password":"` + marker + `"`,
	} {
		c := testCollector(t.TempDir(), &fakeRun{})
		f := antispam.HostFacts{RspamdConfig: antispam.CommandResult{Stdout: dump}}
		c.controllerFacts(&f)
		if i == 0 {
			if f.ControllerErr != nil || !f.Controller.PasswordSet || !f.Controller.EnablePasswordSet {
				t.Fatal("valid passwords did not produce presence facts")
			}
		} else if f.ControllerUnverifiable == nil {
			t.Fatal("malformed dump was not flagged unverifiable")
		}
		if strings.Contains(fmt.Sprintf("%+v %+v %v %v", f.Controller, f.ControllerHost, f.ControllerErr, f.ControllerUnverifiable), marker) {
			t.Fatal("controller facts or error contain a password")
		}
	}
}

func TestCollectControllerUnparseableIsUnverifiable(t *testing.T) {
	for name, dump := range map[string]string{
		"systemd":      `{"worker":[{"controller":{"bind_socket":"systemd:controller","password":"x"}}]}`,
		"null enabled": `{"worker":{"controller":{"bind_socket":"localhost:11334","enabled":null}}}`,
		"null count":   `{"worker":{"controller":{"bind_socket":"localhost:11334","count":null}}}`,
		"unknown type": `{"worker":{"type":["controller"],"bind_socket":"localhost:11334"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := testCollector(t.TempDir(), &fakeRun{results: map[string]antispam.CommandResult{"rspamadm configdump -j": {Stdout: dump}}}).collect(context.Background(), antispam.DefaultSocket)
			if f.ControllerUnverifiable == nil || f.ControllerErr != nil {
				t.Fatalf("ControllerUnverifiable = %v, ControllerErr = %v; want the dump flagged unverifiable, not transient", f.ControllerUnverifiable, f.ControllerErr)
			}
		})
	}
}
