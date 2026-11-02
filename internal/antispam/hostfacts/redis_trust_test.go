package hostfacts

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/dovecot"
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
	c.uid = lookup(map[string]int{"tenant": 12345, "redis": 12345})
	f := antispam.HostFacts{AccountNames: map[string]bool{"tenant": true}}
	if c.trustedRedisOwner(12345, f) {
		t.Fatal("an account UID was trusted through its service-name alias")
	}
	c.uid = func(name string) (int, error) {
		if name == "redis" {
			return 12345, nil
		}
		return -1, errors.New("lookup unavailable")
	}
	if c.trustedRedisOwner(12345, f) {
		t.Fatal("an unresolved account UID was treated as unrelated")
	}
}

// cPanel keeps registry records with no system user, such as its own
// "system" record. A name with no user has no uid to share with Redis.
func TestTrustedRedisOwnerIgnoresRecordWithoutUser(t *testing.T) {
	c, _ := learningCollector(t, &fakeRun{})
	ids := map[string]int{"tenant": 23456, "redis": 12345}
	c.uid = func(name string) (int, error) {
		if id, ok := ids[name]; ok {
			return id, nil
		}
		return -1, user.UnknownUserError(name)
	}
	c.readPasswd = func() ([]byte, error) {
		return []byte("redis:x:12345:12345::/:/bin/false\ntenant:x:23456:23456::/:/bin/false\n"), nil
	}
	f := antispam.HostFacts{AccountNames: map[string]bool{"tenant": true, "system": true}}
	if !c.trustedRedisOwner(12345, f) {
		t.Fatal("a registry record without a system user blocked the redis service user")
	}
	if c.trustedRedisOwner(23456, f) {
		t.Fatal("an account UID was trusted")
	}
}

func TestTrustedRedisOwnerRejectsUnknownUserWithoutLocalProof(t *testing.T) {
	for _, tc := range []struct {
		name   string
		passwd string
		err    error
	}{
		{name: "unavailable database", err: os.ErrNotExist},
		{name: "unreadable database", err: os.ErrPermission},
		{name: "unresolved local alias", passwd: "tenant:x:12345:12345::/:/bin/false\n"},
		{name: "malformed database", passwd: "tenant:x:12345\n"},
		{name: "invalid uid", passwd: "tenant:x:invalid:12345::/:/bin/false\n"},
		{name: "invalid gid", passwd: "tenant:x:12345:invalid::/:/bin/false\n"},
		{name: "invalid name", passwd: "bad name:x:23456:23456::/:/bin/false\n"},
		{name: "malformed unrelated record", passwd: "redis:x:12345:12345::/:/bin/false\nbroken\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := learningCollector(t, &fakeRun{})
			c.uid = func(name string) (int, error) {
				if name == "redis" {
					return 12345, nil
				}
				return -1, user.UnknownUserError(name)
			}
			c.readPasswd = func() ([]byte, error) { return []byte(tc.passwd), tc.err }
			f := antispam.HostFacts{AccountNames: map[string]bool{"tenant": true}}
			if c.trustedRedisOwner(12345, f) {
				t.Fatal("an unresolved account was treated as absent without a readable local record set")
			}
		})
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

// postfixPasswd is a Postfix and Dovecot host's /etc/passwd: rspamd runs as
// _rspamd and virtual mail belongs to vmail.
const postfixPasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_rspamd:x:979:974::/var/lib/rspamd:/usr/sbin/nologin
redis:x:990:990::/var/lib/redis:/usr/sbin/nologin
dovecot:x:991:991::/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:992:992::/nonexistent:/usr/sbin/nologin
postfix:x:993:993::/var/spool/postfix:/usr/sbin/nologin
vmail:x:5000:5000::/srv/vmail:/usr/sbin/nologin
alice:x:1000:1000::/home/alice:/bin/bash
`

// postfixCollector reads passwd as /etc/passwd and resolves names from it
// the way NSS does, first entry first. Its facts are a Postfix host's whose
// rspamd unit runs as _rspamd.
func postfixCollector(t *testing.T, passwd string) (collector, antispam.HostFacts) {
	t.Helper()
	c, _ := learningCollector(t, &fakeRun{})
	c.readPasswd = func() ([]byte, error) { return []byte(passwd), nil }
	c.uid = func(name string) (int, error) {
		for line := range strings.SplitSeq(passwd, "\n") {
			if fields := strings.Split(line, ":"); len(fields) == 7 && fields[0] == name {
				return strconv.Atoi(fields[2])
			}
		}
		return -1, user.UnknownUserError(name)
	}
	f := antispam.HostFacts{Stack: antispam.StackPostfix}
	f.ControllerHost.RspamdUser = "_rspamd"
	f.Socket.RspamdUID = 979
	return c, f
}

// A Postfix host has no account registry: every passwd user except root
// and the pinned service users may run tenant code. The mail uid user is
// not pinned: tenants' sieve scripts and Dovecot's mail processes run as it.
func TestPostfixUntrustedUsersFromPasswd(t *testing.T) {
	c, f := postfixCollector(t, postfixPasswd)
	c.learningRedis(context.Background(), "", &f)
	want := map[string]bool{"daemon": true, "www-data": true, "nobody": true, "vmail": true, "alice": true}
	if f.AccountNamesErr != nil || !maps.Equal(f.AccountNames, want) {
		t.Fatalf("untrusted users = %v (%v), want %v", f.AccountNames, f.AccountNamesErr, want)
	}
	// rspamd's user is pinned by the name its unit runs as; unknown, it is
	// a user like any other.
	f.ControllerHost.RspamdUser = ""
	c.learningRedis(context.Background(), "", &f)
	if f.AccountNamesErr != nil || !f.AccountNames["_rspamd"] || len(f.AccountNames) != len(want)+1 {
		t.Fatalf("unknown rspamd user: %v (%v)", f.AccountNames, f.AccountNamesErr)
	}
	// A record that does not parse may hide a user.
	for name, read := range map[string]func() ([]byte, error){
		"unreadable": func() ([]byte, error) { return nil, os.ErrPermission },
		"malformed":  func() ([]byte, error) { return []byte(postfixPasswd + "broken\n"), nil },
	} {
		c.readPasswd = read
		c.learningRedis(context.Background(), "", &f)
		if f.AccountNamesErr == nil || f.AccountNames != nil {
			t.Fatalf("%s passwd: %v (%v)", name, f.AccountNames, f.AccountNamesErr)
		}
	}
}

// On Postfix the Redis owner is trusted as on cPanel: root, rspamd's
// service user or the redis user, and only while no untrusted user shares
// its uid. Dovecot's and Postfix's users are pinned, not trusted with Redis.
func TestTrustedRedisOwnerPostfix(t *testing.T) {
	vmailIsRedis := strings.Replace(postfixPasswd, "vmail:x:5000:5000", "vmail:x:990:990", 1)
	for _, tc := range []struct {
		name   string
		passwd string
		uid    int
		want   bool
	}{
		{name: "root", passwd: postfixPasswd, uid: 0, want: true},
		{name: "redis", passwd: postfixPasswd, uid: 990, want: true},
		{name: "rspamd", passwd: postfixPasswd, uid: 979, want: true},
		{name: "vmail", passwd: postfixPasswd, uid: 5000},
		{name: "dovecot", passwd: postfixPasswd, uid: 991},
		{name: "dovenull", passwd: postfixPasswd, uid: 992},
		{name: "postfix", passwd: postfixPasswd, uid: 993},
		{name: "nobody", passwd: postfixPasswd, uid: 65534},
		{name: "login user", passwd: postfixPasswd, uid: 1000},
		{name: "mail uid shares redis's", passwd: vmailIsRedis, uid: 990},
		{name: "alias of rspamd", passwd: postfixPasswd + "builder:x:979:979::/home/builder:/bin/sh\n", uid: 979},
		{name: "passwd malformed", passwd: postfixPasswd + "broken\n", uid: 990},
		{name: "passwd malformed root", passwd: postfixPasswd + "broken\n", uid: 0, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, f := postfixCollector(t, tc.passwd)
			c.learningRedis(context.Background(), "", &f)
			if got := c.trustedRedisOwner(tc.uid, f); got != tc.want {
				t.Fatalf("trusted=%v, want %v (untrusted users %v, %v)", got, tc.want, f.AccountNames, f.AccountNamesErr)
			}
		})
	}

	// The socket's group grants access: only root, redis and rspamd's user
	// may be in it.
	for members, want := range map[string]string{
		"redis,_rspamd":  "",
		"redis,vmail":    "the Redis socket: socket reachable by other users",
		"redis,dovecot":  "the Redis socket: socket reachable by other users",
		"redis,dovenull": "the Redis socket: socket reachable by other users",
		"redis,postfix":  "the Redis socket: socket reachable by other users",
	} {
		c, f := postfixCollector(t, postfixPasswd)
		c.learningRedis(context.Background(), "", &f)
		const socket = "/run/redis-csm/redis.sock"
		root := antispam.PathFacts{Path: "/", Mode: fs.ModeDir | 0o755}
		run := antispam.PathFacts{Path: "/run", Mode: fs.ModeDir | 0o755}
		f.Redis = antispam.RedisFacts{Endpoint: socket, Unix: true, ServiceUID: 990, GroupMembers: strings.Split(members, ","),
			Socket: antispam.SocketFacts{
				Socket:  antispam.PathFacts{Path: socket, UID: 990, GID: 974, Mode: fs.ModeSocket | 0o770},
				Parents: []antispam.PathFacts{root, run, {Path: "/run/redis-csm", UID: 990, GID: 974, Mode: fs.ModeDir | 0o750}},
			},
			Port: "0", TLSPort: "0", MaxMemory: 1 << 30, MaxMemoryKnown: true, Used: 1 << 20, Policy: "noeviction", AppendOnly: "yes", Version: "7.2.4"}
		err := antispam.CheckLearningRedis(dedicatedSettings(socket), f)
		if got := fmt.Sprint(err); want == "" && err != nil || want != "" && got != want {
			t.Errorf("group %s: %v, want %q", members, err, want)
		}
	}
}

// snapshotOf serves snap and err as Dovecot's answer and counts the calls.
func snapshotOf(snap dovecot.Snapshot, err error, calls *int) func(context.Context) (dovecot.Snapshot, error) {
	return func(context.Context) (dovecot.Snapshot, error) {
		*calls++
		return snap, err
	}
}

// On Postfix the pass lists Dovecot's mailboxes before it judges Redis: the
// uids mail is stored as, and the users it skips, reach the facts, and
// every passwd name of a mail uid is untrusted, pinned or not (L12). A
// failed or incomplete listing is an error and adds no names.
func TestCollectLearningPostfixDovecot(t *testing.T) {
	snap := dovecot.Snapshot{Complete: true,
		Mailboxes: []dovecot.DovecotMailbox{
			{User: "a@example.com", Domain: "example.com", UID: 5000},
			{User: "b@example.com", Domain: "example.com", UID: 991},
			{User: "c@example.net", Domain: "example.net", UID: 5000},
		},
		Skips: []dovecot.Skip{{User: "d@example.org", Reason: dovecot.SkipDriver}},
	}
	c, f := postfixCollector(t, postfixPasswd)
	calls := 0
	c.dovecot = snapshotOf(snap, nil, &calls)
	c.learningFacts(context.Background(), antispam.Settings{Learning: true}, &f)
	if calls != 1 || f.Dovecot.Err != nil || !slices.Equal(f.Dovecot.UIDs, []int{991, 5000}) || !slices.Equal(f.Dovecot.Skips, snap.Skips) {
		t.Fatalf("calls %d, Dovecot facts %+v", calls, f.Dovecot)
	}
	if f.AccountNamesErr != nil || !f.AccountNames["vmail"] || !f.AccountNames["dovecot"] || f.AccountNames["postfix"] || f.AccountNames["redis"] {
		t.Fatalf("untrusted users = %v (%v)", f.AccountNames, f.AccountNamesErr)
	}
	for name, tc := range map[string]struct {
		snap dovecot.Snapshot
		err  error
	}{
		"error":      {err: dovecot.ErrCannotIterate},
		"incomplete": {snap: dovecot.Snapshot{Mailboxes: snap.Mailboxes}},
	} {
		failed, ff := postfixCollector(t, postfixPasswd)
		failed.dovecot = snapshotOf(tc.snap, tc.err, &calls)
		failed.learningFacts(context.Background(), antispam.Settings{Learning: true}, &ff)
		if ff.Dovecot.Err == nil || tc.err != nil && !errors.Is(ff.Dovecot.Err, tc.err) || len(ff.Dovecot.UIDs) != 0 || ff.AccountNames["dovecot"] {
			t.Fatalf("%s: Dovecot facts %+v, untrusted %v", name, ff.Dovecot, ff.AccountNames)
		}
	}
	// cPanel reads nothing from Dovecot.
	c, f = postfixCollector(t, postfixPasswd)
	f.Stack = antispam.StackExim
	calls = 0
	c.dovecot = snapshotOf(snap, nil, &calls)
	c.learningFacts(context.Background(), antispam.Settings{Learning: true}, &f)
	if calls != 0 || f.Dovecot.UIDs != nil {
		t.Fatalf("Exim listed Dovecot: calls %d, facts %+v", calls, f.Dovecot)
	}
}

// The controller trusts rspamd's uid (ruling P6). A user that may run
// tenant code and resolves to it is a proven share. When CSM cannot rule a
// share out, because the account list, a uid lookup or /etc/passwd cannot
// be read, that is an error, not a share. A proven share wins over another
// account's error.
func TestCollectRspamdUIDShared(t *testing.T) {
	for _, tc := range []struct {
		name    string
		passwd  string
		mail    []int
		shared  bool
		wantErr bool
	}{
		{name: "distinct", passwd: postfixPasswd},
		{name: "alias of rspamd", passwd: postfixPasswd + "builder:x:979:979::/home/builder:/bin/sh\n", shared: true},
		{name: "mail as rspamd", passwd: postfixPasswd, mail: []int{979}, shared: true},
		{name: "passwd malformed", passwd: postfixPasswd + "broken\n", wantErr: true},
	} {
		t.Run("postfix "+tc.name, func(t *testing.T) {
			c, f := postfixCollector(t, tc.passwd)
			f.ControllerHost.RspamdUID = 979
			snap := dovecot.Snapshot{Complete: true}
			for _, uid := range tc.mail {
				snap.Mailboxes = append(snap.Mailboxes, dovecot.DovecotMailbox{User: "a@example.com", Domain: "example.com", UID: uid})
			}
			calls := 0
			c.dovecot = snapshotOf(snap, nil, &calls)
			c.learningFacts(context.Background(), antispam.Settings{Learning: true}, &f)
			if f.RspamdUIDShared != tc.shared || (f.RspamdUIDErr != nil) != tc.wantErr {
				t.Fatalf("shared=%v err=%v, want %v/%v (untrusted %v)", f.RspamdUIDShared, f.RspamdUIDErr, tc.shared, tc.wantErr, f.AccountNames)
			}
		})
	}
	const cleanPasswd = "tenant:x:23456:23456::/home/tenant:/bin/bash\n"
	for _, tc := range []struct {
		name     string
		accounts []string // files in /var/cpanel/users; nil: the directory is missing
		uids     map[string]int
		passwd   string
		uid      int
		shared   bool
		wantErr  bool
	}{
		{name: "distinct", accounts: []string{"tenant"}, uids: map[string]int{"tenant": 23456}, uid: 979},
		{name: "account shares rspamd's uid", accounts: []string{"tenant"}, uids: map[string]int{"tenant": 979}, uid: 979, shared: true},
		{name: "account lookup fails", accounts: []string{"tenant"}, uids: map[string]int{}, uid: 979, wantErr: true},
		// Map order varies: several failing accounts and repeated reads
		// make an error that hides the share show up.
		{name: "share wins over a failed lookup", accounts: []string{"other1", "other2", "other3", "other4", "other5", "other6", "other7", "tenant"}, uids: map[string]int{"tenant": 979}, uid: 979, shared: true},
		{name: "accounts unreadable", uids: map[string]int{"tenant": 23456}, uid: 979, wantErr: true},
		// cPanel's own system record has no user: absent from passwd it
		// shares nothing, but a passwd CSM cannot parse cannot prove that.
		{name: "system record", accounts: []string{"system", "tenant"}, uids: map[string]int{"tenant": 23456}, passwd: cleanPasswd, uid: 979},
		{name: "system record, passwd malformed", accounts: []string{"system", "tenant"}, uids: map[string]int{"tenant": 23456}, passwd: cleanPasswd + "broken\n", uid: 979, wantErr: true},
		{name: "unknown user listed in passwd as rspamd", accounts: []string{"system"}, uids: map[string]int{}, passwd: "system:x:979:979::/:/bin/false\n", uid: 979, shared: true},
		// NSS and passwd disagree: CSM cannot tell which uid it has.
		{name: "unknown user listed in passwd", accounts: []string{"system"}, uids: map[string]int{}, passwd: "system:x:5555:5555::/:/bin/false\n", uid: 979, wantErr: true},
		// rspamd's uid unknown is reported on its own; nothing to compare.
		{name: "rspamd unknown", accounts: []string{"tenant"}, uids: map[string]int{}, uid: -1},
	} {
		t.Run("cpanel "+tc.name, func(t *testing.T) {
			c, _ := learningCollector(t, &fakeRun{})
			if tc.accounts != nil {
				mkdir(t, c.layout.CPanelUsers)
			}
			for _, a := range tc.accounts {
				write(t, filepath.Join(c.layout.CPanelUsers, a), "")
			}
			c.uid = func(name string) (int, error) {
				if id, ok := tc.uids[name]; ok {
					return id, nil
				}
				if name == "system" {
					return -1, user.UnknownUserError(name)
				}
				return -1, fmt.Errorf("lookup of %s failed", name)
			}
			c.readPasswd = func() ([]byte, error) { return []byte(tc.passwd), nil }
			for range 8 {
				f := antispam.HostFacts{Stack: antispam.StackExim}
				f.ControllerHost.RspamdUID = tc.uid
				c.learningFacts(context.Background(), antispam.Settings{Learning: true}, &f)
				if f.RspamdUIDShared != tc.shared || (f.RspamdUIDErr != nil) != tc.wantErr {
					t.Fatalf("shared=%v err=%v, want %v/%v", f.RspamdUIDShared, f.RspamdUIDErr, tc.shared, tc.wantErr)
				}
			}
		})
	}
}
