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
	t.Cleanup(func() { l.Close() })
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
