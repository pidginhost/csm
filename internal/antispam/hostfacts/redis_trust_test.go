package hostfacts

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func TestRedisPathRejectsTenantSymlink(t *testing.T) {
	d := t.TempDir()
	shared := filepath.Join(d, "shared")
	mkdir(t, shared)
	if err := os.Chmod(shared, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	sock := serve(t, d, pong)
	link := filepath.Join(shared, "redis.sock")
	symlink(t, sock, link)
	relative := filepath.Join(shared, "relative.sock")
	symlink(t, "../"+filepath.Base(sock), relative)
	dirLink := filepath.Join(shared, "dir")
	symlink(t, d, dirLink)
	// Model root-owned directories and socket, with a tenant-owned link.
	// Ownership is synthetic so this proof does not require chown privileges.
	linkOwner := 12345
	stat := func(p string) (antispam.PathFacts, error) {
		f, err := pathFacts(p)
		f.UID = 0
		if f.Mode&os.ModeSymlink != 0 {
			f.UID = linkOwner
		}
		return f, err
	}
	for _, endpoint := range []string{link, relative, filepath.Join(dirLink, filepath.Base(sock)), shared + "/../shared/redis.sock"} {
		if protectedRedisPath(endpoint, 0, stat) {
			t.Errorf("a tenant-owned symlink was trusted: %s", endpoint)
		}
		linkOwner = 0
		if !protectedRedisPath(endpoint, 0, stat) {
			t.Errorf("a root-owned symlink was rejected: %s", endpoint)
		}
		linkOwner = 12345
	}
	if !protectedRedisPath(sock, 0, stat) {
		t.Fatal("the protected socket was rejected")
	}
}

func TestRedisPathRejectsUnsafeDirectories(t *testing.T) {
	d := t.TempDir()
	sock := serve(t, d, pong)
	for name, mutate := range map[string]func(*antispam.PathFacts){
		"tenant owner": func(p *antispam.PathFacts) { p.UID = 23456 },
		"group write":  func(p *antispam.PathFacts) { p.Mode |= 0o020 },
		"other write":  func(p *antispam.PathFacts) { p.Mode |= 0o002 },
		"ACL":          func(p *antispam.PathFacts) { p.ExtACL = true },
	} {
		t.Run(name, func(t *testing.T) {
			stat := func(p string) (antispam.PathFacts, error) {
				f, err := pathFacts(p)
				f.UID = 0
				if p == d {
					mutate(&f)
				}
				return f, err
			}
			if protectedRedisPath(sock, 0, stat) {
				t.Fatal("unsafe directory accepted")
			}
		})
	}
	if protectedRedisPath(sock, 0, func(string) (antispam.PathFacts, error) {
		return antispam.PathFacts{}, errors.New("stat unavailable")
	}) {
		t.Fatal("an unreadable directory was accepted")
	}
}

func TestTrustedRedisOwnerRejectsAccountUIDAlias(t *testing.T) {
	c, _ := learningCollector(t, &fakeRun{})
	c.userName = func(string) (string, error) { return "redis", nil }
	c.uid = lookup(map[string]int{"tenant": 12345})
	f := antispam.HostFacts{AccountNames: map[string]bool{"tenant": true}}
	if c.trustedRedisOwner(12345, f) {
		t.Fatal("an account UID was trusted through its service-name alias")
	}
	c.uid = func(string) (int, error) { return -1, errors.New("lookup unavailable") }
	if c.trustedRedisOwner(12345, f) {
		t.Fatal("an unresolved account UID was treated as unrelated")
	}
}

// Trusted owners are pinned: root, rspamd's service user and the system user
// named redis, and never a uid a cPanel account shares.
func TestTrustedRedisOwner(t *testing.T) {
	for _, tc := range []struct {
		name       string
		uid        int
		accounts   map[string]bool
		accountErr error
		want       bool
	}{
		{name: "root", uid: 0, accountErr: errors.New("accounts unavailable"), want: true},
		{name: "redis service", uid: 12345, want: true},
		{name: "rspamd service", uid: 979, want: true},
		{name: "shared user", uid: 99},
		{name: "account", uid: 23456},
		{name: "account named redis", uid: 12345, accounts: map[string]bool{"tenant": true, "redis": true}},
		{name: "accounts failed", uid: 12345, accountErr: errors.New("accounts unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := learningCollector(t, &fakeRun{})
			c.uid = lookup(map[string]int{"tenant": 23456, "redis": 12345, "nobody": 99})
			accounts := tc.accounts
			if accounts == nil {
				accounts = map[string]bool{"tenant": true}
			}
			f := antispam.HostFacts{AccountNames: accounts, AccountNamesErr: tc.accountErr}
			f.Socket.RspamdUID = 979
			if got := c.trustedRedisOwner(tc.uid, f); got != tc.want {
				t.Fatalf("trusted=%v, want %v", got, tc.want)
			}
		})
	}
}
