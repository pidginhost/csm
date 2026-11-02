package dovecot

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// record is one command captured from a Dovecot 2.3 container by
// testdata/capture.sh.
type record struct {
	Argv   []string `json:"argv"`
	Stdout string   `json:"stdout"`
	Stderr string   `json:"stderr"`
	Exit   int      `json:"exit"`
}

func capture(t testing.TB, name string) []record {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var c struct{ Commands []record }
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	return c.Commands
}

// exitError is a real exit status: Snapshot reads the code.
func exitError(t testing.TB, code int, stderr string) error {
	t.Helper()
	return shellError(t, fmt.Sprintf("exit %d", code), stderr)
}

func shellError(t testing.TB, script, stderr string) error {
	t.Helper()
	var exit *exec.ExitError
	if err := exec.Command("sh", "-c", script).Run(); !errors.As(err, &exit) {
		t.Fatalf("sh -c %q: %v", script, err)
	}
	exit.Stderr = []byte(stderr)
	return exit
}

// replay serves the captured commands by exact argv, so the commands
// Snapshot runs are the ones real Dovecot answered.
func replay(t *testing.T, recs []record) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		argv := append([]string{name}, args...)
		for _, r := range recs {
			if slices.Equal(r.Argv, argv) {
				if r.Exit != 0 {
					return []byte(r.Stdout), exitError(t, r.Exit, r.Stderr)
				}
				return []byte(r.Stdout), nil
			}
		}
		t.Errorf("command not captured: %q", argv)
		return nil, errors.New("not captured")
	}
}

// dovecotPaths returns where Dovecot itself puts the named folders of user.
func dovecotPaths(t *testing.T, recs []record, user string, boxes ...string) []string {
	t.Helper()
	var paths []string
	for _, box := range boxes {
		argv := []string{"doveadm", "mailbox", "path", "-u", user, box}
		i := slices.IndexFunc(recs, func(r record) bool { return slices.Equal(r.Argv, argv) })
		if i < 0 || recs[i].Exit != 0 {
			t.Fatalf("no captured path for %q", argv)
		}
		paths = append(paths, strings.TrimSuffix(recs[i].Stdout, "\n"))
	}
	slices.Sort(paths)
	return paths
}

func TestSnapshotMatchesDovecotFolders(t *testing.T) {
	recs := capture(t, "maildir")
	snap, err := Dovecot{Run: replay(t, recs)}.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	boxes := []string{"INBOX.Junk", "INBOX.Courrier indésirable", "INBOX.Spam & Co"}
	junk := func(root string) []string {
		return []string{root + "/.Courrier ind&AOk-sirable", root + "/.Junk", root + "/.Spam &- Co"}
	}
	want := Snapshot{
		Mailboxes: []DovecotMailbox{
			{User: "-x@example.com", Domain: "example.com", UID: 1000, GID: 1000, Home: "/srv/vmail/example.com/x", Junk: junk("/srv/vmail/example.com/x/Maildir")},
			{User: "alice@example.com", Domain: "example.com", UID: 1000, GID: 1000, Home: "/srv/vmail/example.com/alice", Junk: dovecotPaths(t, recs, "alice@example.com", boxes...)},
			{User: "bob@example.com", Domain: "example.com", UID: 1000, GID: 1000, Home: "/srv/vmail/example.com/bob", Junk: dovecotPaths(t, recs, "bob@example.com", boxes...)},
			{User: "carol@example.net", Domain: "example.net", UID: 1001, GID: 1001, Home: "/srv/vmail/example.net/carol", Junk: dovecotPaths(t, recs, "carol@example.net", boxes...)},
			{User: "dave", UID: 1002, GID: 1002, Home: "/home/dave", Junk: junk("/home/dave/Maildir")},
		},
		Skips: []Skip{
			{Reason: SkipInvalidName},
			{User: "erin@example.net", Reason: SkipDriver},
			{User: "frank@example.net", Reason: SkipLayoutFS},
			{User: "grace@example.com", Reason: SkipPluginZlib},
			{User: "henry@example.com", Reason: SkipLookupFailed},
			{User: "rel@example.com", Reason: SkipLookupFailed},
			{User: "zero@example.com", Reason: SkipLookupFailed},
		},
		Complete: true,
	}
	if !reflect.DeepEqual(snap, want) {
		t.Fatalf("snapshot:\n got %+v\nwant %+v", snap, want)
	}
	if got := junk("/srv/vmail/example.com/alice/Maildir"); !slices.Equal(got, want.Mailboxes[1].Junk) {
		t.Fatalf("Dovecot paths %q, formula %q", want.Mailboxes[1].Junk, got)
	}
}

// Captured: a relative home makes doveadm exit EX_TEMPFAIL after printing
// the other users of the batch.
func TestDetailsKeepRecordsOnTempFail(t *testing.T) {
	recs := capture(t, "maildir")
	i := slices.IndexFunc(recs, func(r record) bool { return r.Argv[0] == "doveconf" })
	conf, err := parseConfig([]byte(recs[i].Stdout))
	if err != nil {
		t.Fatal(err)
	}
	found, err := Dovecot{Run: replay(t, recs)}.details(context.Background(), conf, []string{"alice@example.com", "rel@example.com"})
	if err != nil || len(found) != 1 || found["alice@example.com"].home != "/srv/vmail/example.com/alice" {
		t.Fatalf("found %+v, err %v", found, err)
	}
}

func TestSnapshotSlashSeparatorUTF8AndNamespaceLocation(t *testing.T) {
	recs := capture(t, "slash")
	snap, err := Dovecot{Run: replay(t, recs)}.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	boxes := []string{"Spam/Sub", "Pourriel é", "Archive/Junk"}
	want := Snapshot{
		Mailboxes: []DovecotMailbox{
			{User: "alice@example.com", Domain: "example.com", UID: 1000, GID: 1000, Home: "/srv/vmail/example.com/alice", Junk: dovecotPaths(t, recs, "alice@example.com", boxes...)},
			{User: "bob@example.org", Domain: "example.org", UID: 1000, GID: 1000, Home: "/srv/vmail/example.org/bob", Junk: dovecotPaths(t, recs, "bob@example.org", boxes...)},
		},
		Complete: true,
	}
	if !reflect.DeepEqual(snap, want) {
		t.Fatalf("snapshot:\n got %+v\nwant %+v", snap, want)
	}
}

func TestSnapshotUserdbCannotIterate(t *testing.T) {
	snap, err := Dovecot{Run: replay(t, capture(t, "static"))}.Snapshot(context.Background())
	if !errors.Is(err, ErrCannotIterate) {
		t.Fatalf("err = %v, want ErrCannotIterate", err)
	}
	if !reflect.DeepEqual(snap, Snapshot{}) {
		t.Fatalf("snapshot = %+v, want empty", snap)
	}
}

// listFailure is Dovecot 2.3's answer to any listing the auth server
// failed: a userdb that cannot iterate, or a backend that failed to.
const listFailure = "Error: auth-master: userdb list: User listing returned failure\nFatal: user listing failed\n"

// The listing failure means "cannot list users" only when doveconf shows no
// userdb able to iterate. Otherwise an SQL, LDAP or passwd-file backend
// failed, which is an outage, not a configuration learning cannot use.
func TestSnapshotListingFailureByUserdb(t *testing.T) {
	const captured = "userdb {\n  args = /etc/dovecot/users\n  driver = passwd-file\n}\n"
	sql := "userdb {\n  args = /etc/dovecot/dovecot-sql.conf.ext\n  driver = sql\n}\n"
	for conf, cannot := range map[string]bool{
		captured: false,
		sql:      false,
		"userdb {\n  args = /etc/dovecot/dovecot-ldap.conf.ext\n  driver = ldap\n}\n":                false,
		"userdb {\n  driver = passwd\n}\n":                                                           false,
		"userdb {\n  args = username_format=%n /etc/dovecot/users\n  driver = passwd-file\n}\n":      false,
		"userdb {\n  args = /etc/dovecot/100%%users\n  driver = passwd-file\n}\n":                    false,
		"userdb {\n  driver = prefetch\n}\n" + sql:                                                   false,
		"userdb {\n  driver = lua\n  args = file=/etc/dovecot/auth.lua\n}\n":                         false,
		"userdb {\n  driver = prefetch\n}\n":                                                         true,
		"userdb {\n  args = uid=vmail gid=vmail home=/srv/vmail/%d/%n\n  driver = static\n}\n":       true,
		"userdb {\n  args = /usr/local/bin/checkpassword\n  driver = checkpassword\n}\n":             true,
		"userdb {\n  args = /etc/dovecot/%d/passwd\n  driver = passwd-file\n}\n":                     true,
		"userdb {\n  args = username_format=%n /etc/dovecot/%Ld.passwd\n  driver = passwd-file\n}\n": true,
		"userdb {\n  driver = \"static\"\n}\nuserdb {\n  driver = prefetch\n}\n":                     true,
	} {
		h := newHost(t, "alice@example.com")
		h.edit(captured, conf)
		h.listErr = exitError(t, 75, listFailure)
		snap, err := h.snapshot()
		if err == nil || errors.Is(err, ErrCannotIterate) != cannot || !reflect.DeepEqual(snap, Snapshot{}) {
			t.Errorf("%q: snapshot %+v, err %v, want cannot iterate %v", conf, snap, err, cannot)
		}
	}
}

// Users rechecks removals: names only, as Snapshot would key them, from one
// listing and no lookup. A failed or empty listing is an error. The recheck
// follows a complete listing and reads no configuration, so a failed
// listing is an outage, never "cannot list users".
func TestUsersListsIdentitiesOnly(t *testing.T) {
	h := newHost(t, "Alice@Example.com", "bob@example.com", "bad name", "dave", "alice@example.com")
	got, err := Dovecot{Run: h.run}.Users(context.Background())
	if err != nil || !slices.Equal(got, []string{"alice@example.com", "bob@example.com", "dave"}) || h.listings != 1 || h.batches != nil {
		t.Fatalf("users %q, err %v, %d listings, lookups %q", got, err, h.listings, h.batches)
	}
	if _, err := (Dovecot{Run: replay(t, capture(t, "static"))}).Users(context.Background()); err == nil || errors.Is(err, ErrCannotIterate) {
		t.Fatalf("static userdb: err %v", err)
	}
	h = newHost(t, "alice@example.com")
	h.listErr = exitError(t, 75, listFailure)
	if _, err := (Dovecot{Run: h.run}).Users(context.Background()); err == nil || errors.Is(err, ErrCannotIterate) {
		t.Fatalf("failed listing: err %v", err)
	}
	h = newHost(t)
	h.list = "\n"
	if got, err := (Dovecot{Run: h.run}).Users(context.Background()); err == nil {
		t.Fatalf("empty listing: users %q", got)
	}
}

func TestSnapshotDovecot24ByVersion(t *testing.T) {
	// Only the version is captured: any later command fails the test.
	snap, err := Dovecot{Run: replay(t, capture(t, "v24"))}.Snapshot(context.Background())
	if !errors.Is(err, ErrDovecot24) {
		t.Fatalf("err = %v, want ErrDovecot24", err)
	}
	if snap.Complete || snap.Mailboxes != nil {
		t.Fatalf("snapshot = %+v, want empty", snap)
	}
}

func TestSnapshotRefusesOtherVersions(t *testing.T) {
	for _, v := range []string{"2.2.36 (1f10bfa63)\n", "3.0.0 (x)\n", "", "dovecot\n", "2.\n"} {
		h := newHost(t, "alice@example.com")
		h.version = v
		_, err := Dovecot{Run: h.run}.Snapshot(context.Background())
		if err == nil || (v == "3.0.0 (x)\n") != errors.Is(err, ErrDovecot24) {
			t.Errorf("version %q: err = %v", v, err)
		}
	}
}

// host answers like the captured Dovecot 2.3 host, from fields a test can
// change. Detail lines copy the template's locations verbatim, which matches
// Dovecot for locations without variables.
type host struct {
	t                  *testing.T
	version, conf      string
	list, final        string
	fields             map[string]string
	listErr, detailErr error
	listOut, detailOut []byte
	listings           int
	batches            [][]string
	// detailExit, when set, is the status of every lookup. Otherwise a
	// lookup with an unknown user exits missingExit, 67 when unset, as
	// Dovecot does, and 0 when every user is known.
	detailExit, missingExit int
}

func newHost(t *testing.T, users ...string) *host {
	t.Helper()
	recs := capture(t, "maildir")
	h := &host{t: t, fields: map[string]string{}}
	for _, r := range recs {
		switch {
		case r.Argv[0] == "dovecot":
			h.version = r.Stdout
		case r.Argv[0] == "doveconf":
			h.conf = r.Stdout
		case len(r.Argv) > 2 && r.Argv[2] == "-e":
			for line := range strings.Lines(r.Stdout) {
				if f := strings.Split(strings.TrimSuffix(line, "\n"), "\t"); len(f) > 6 {
					h.fields[f[0]] = strings.Join(f[:6], "\t")
				}
			}
		}
	}
	h.list = strings.Join(users, "\n") + "\n"
	return h
}

// edit changes the captured configuration, failing if from is not in it.
func (h *host) edit(from, to string) {
	h.t.Helper()
	if !strings.Contains(h.conf, from) {
		h.t.Fatalf("configuration has no %q", from)
	}
	h.conf = strings.ReplaceAll(h.conf, from, to)
}

// set replaces field i of user's detail line.
func (h *host) set(user string, i int, value string) {
	f := strings.Split(h.fields[user], "\t")
	f[i] = value
	h.fields[user] = strings.Join(f, "\t")
}

func (h *host) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if d, ok := ctx.Deadline(); !ok || time.Until(d) > commandTimeout {
		h.t.Errorf("%s runs without the %v bound", name, commandTimeout)
	}
	argv := append([]string{name}, args...)
	switch {
	case slices.Equal(argv, []string{"dovecot", "--version"}):
		return []byte(h.version), nil
	case slices.Equal(argv, []string{"doveconf", "-n"}):
		return []byte(h.conf), nil
	case slices.Equal(argv, []string{"doveadm", "user", "*"}):
		h.listings++
		switch {
		case h.listErr != nil:
			return nil, h.listErr
		case h.listOut != nil:
			return h.listOut, nil
		case h.listings > 1 && h.final != "":
			return []byte(h.final), nil
		}
		return []byte(h.list), nil
	case len(argv) > 5 && slices.Equal(argv[:3], []string{"doveadm", "user", "-e"}) && argv[4] == "--":
		h.batches = append(h.batches, argv[5:])
		if h.detailErr != nil {
			return nil, h.detailErr
		}
		if h.detailOut != nil {
			return h.detailOut, nil
		}
		tmpl := strings.Split(argv[3], "\t")
		if !slices.Equal(tmpl[:6], []string{"%u", "%{uid}", "%{gid}", "%h", "%{userdb:mail}", "%{userdb:mail_plugins}"}) {
			h.t.Errorf("template %q", argv[3])
		}
		var out bytes.Buffer
		var missing []string
		for _, u := range argv[5:] {
			// Dovecot looks names up in lower case (auth_username_format).
			f, ok := h.fields[strings.ToLower(u)]
			if !ok {
				missing = append(missing, u)
				out.WriteString("\n")
				continue
			}
			out.WriteString(f)
			for _, v := range tmpl[6:] {
				if v == "%u" {
					v = strings.Split(f, "\t")[0]
				}
				out.WriteString("\t" + v)
			}
			out.WriteString("\n\n")
		}
		code := h.detailExit
		if code == 0 && missing != nil {
			code = cmp.Or(h.missingExit, 67)
		}
		if code != 0 {
			return out.Bytes(), exitError(h.t, code, "userdb lookup failed\n")
		}
		return out.Bytes(), nil
	}
	h.t.Errorf("unexpected command %q", argv)
	return nil, errors.New("unexpected command")
}

func (h *host) snapshot() (Snapshot, error) {
	return Dovecot{Run: h.run}.Snapshot(context.Background())
}

func reasons(s Snapshot) map[string]string {
	m := map[string]string{}
	for _, k := range s.Skips {
		m[k.User] = k.Reason
	}
	return m
}

func TestSnapshotThreeUsersTwoDomains(t *testing.T) {
	h := newHost(t, "alice@example.com", "bob@example.com", "carol@example.net")
	snap, err := h.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range snap.Mailboxes {
		got = append(got, m.User+" "+m.Domain+" "+m.Junk[1])
	}
	want := []string{
		"alice@example.com example.com /srv/vmail/example.com/alice/Maildir/.Junk",
		"bob@example.com example.com /srv/vmail/example.com/bob/Mail/.Junk",
		"carol@example.net example.net /srv/vmail/example.net/carol/Maildir/.Junk",
	}
	if !snap.Complete || len(snap.Skips) != 0 || !slices.Equal(got, want) {
		t.Fatalf("snapshot %+v, mailboxes %q", snap, got)
	}
}

func TestSnapshotPluginsSkipEveryMailbox(t *testing.T) {
	for _, c := range []struct{ from, to, reason string }{
		{`mail_plugins = " quota"`, `mail_plugins = " quota zlib"`, SkipPluginZlib},
		{`mail_plugins = " quota sieve"`, `mail_plugins = " quota sieve zlib"`, SkipPluginZlib},
		{`mail_plugins = " quota"`, `mail_plugins = " quota mail_crypt"`, SkipPluginMailCrypt},
		{`mail_plugins = " quota sieve"`, `mail_plugins = " quota sieve mail_crypt_acl mail_crypt"`, SkipPluginMailCrypt},
	} {
		h := newHost(t, "alice@example.com", "bob@example.com", "dave")
		h.edit(c.from, c.to)
		snap, err := h.snapshot()
		want := map[string]string{"alice@example.com": c.reason, "bob@example.com": c.reason, "dave": c.reason}
		if err != nil || !snap.Complete || snap.Mailboxes != nil || !reflect.DeepEqual(reasons(snap), want) {
			t.Errorf("%s: snapshot %+v, err %v", c.to, snap, err)
		}
	}
}

func TestSnapshotUserdbPluginsSkipThatMailbox(t *testing.T) {
	h := newHost(t, "alice@example.com", "bob@example.com")
	h.set("bob@example.com", 5, "quota mail_crypt")
	snap, err := h.snapshot()
	if err != nil || len(snap.Mailboxes) != 1 || snap.Mailboxes[0].User != "alice@example.com" ||
		!reflect.DeepEqual(reasons(snap), map[string]string{"bob@example.com": SkipPluginMailCrypt}) {
		t.Fatalf("snapshot %+v, err %v", snap, err)
	}
}

func TestSnapshotRefusesRootUID(t *testing.T) {
	h := newHost(t, "alice@example.com", "bob@example.com")
	h.set("alice@example.com", 1, "0")
	snap, err := h.snapshot()
	if err != nil || len(snap.Mailboxes) != 1 || snap.Mailboxes[0].User != "bob@example.com" ||
		!reflect.DeepEqual(reasons(snap), map[string]string{"alice@example.com": SkipUIDRoot}) {
		t.Fatalf("snapshot %+v, err %v", snap, err)
	}
}

func TestSnapshotRefusesHomeOutsideAbsolutePath(t *testing.T) {
	for _, home := range []string{"relative/home", "", "/srv/vmail/../../root", "~"} {
		h := newHost(t, "alice@example.com")
		h.set("alice@example.com", 3, home)
		snap, err := h.snapshot()
		if err != nil || snap.Mailboxes != nil || !reflect.DeepEqual(reasons(snap), map[string]string{"alice@example.com": SkipInvalidHome}) {
			t.Errorf("home %q: snapshot %+v, err %v", home, snap, err)
		}
	}
	// A home is refused even where the location does not use it.
	for _, home := range []string{"relative/home", "/srv/vmail/../../root"} {
		h := newHost(t, "alice@example.com")
		h.set("alice@example.com", 3, home)
		h.set("alice@example.com", 4, "maildir:/srv/mail/alice")
		snap, err := h.snapshot()
		if err != nil || snap.Mailboxes != nil || !reflect.DeepEqual(reasons(snap), map[string]string{"alice@example.com": SkipInvalidHome}) {
			t.Errorf("home %q with an absolute location: snapshot %+v, err %v", home, snap, err)
		}
	}
}

func TestSnapshotAbsoluteLocationNeedsNoHome(t *testing.T) {
	h := newHost(t, "alice@example.com")
	h.set("alice@example.com", 3, "")
	h.set("alice@example.com", 4, "maildir:/srv/mail/alice")
	snap, err := h.snapshot()
	if err != nil || len(snap.Mailboxes) != 1 || snap.Mailboxes[0].Home != "" || snap.Mailboxes[0].Junk[1] != "/srv/mail/alice/.Junk" {
		t.Fatalf("snapshot %+v, err %v", snap, err)
	}
}

func TestSnapshotUnsupportedLocations(t *testing.T) {
	for mail, reason := range map[string]string{
		"mdbox:~/mdbox":                     SkipDriver,
		"sdbox:~/sdbox":                     SkipDriver,
		"mbox:~/mail:INBOX=/var/mail/alice": SkipDriver,
		"~/Maildir":                         SkipDriver,
		"maildir:~/Maildir:LAYOUT=fs":       SkipLayoutFS,
		"maildir:~/Maildir:LAYOUT=index":    SkipLocation,
		"maildir:~/Maildir:DIRNAME=mail":    SkipLocation,
		"maildir:~/Maildir:FULLDIRNAME=x":   SkipLocation,
		"maildir:~/Maildir:MAILBOXDIR=box":  SkipLocation,
		"maildir:~/Mail::dir":               SkipLocation,
		"maildir:Maildir":                   SkipLocation,
		"maildir:~alice/Maildir":            SkipLocation,
		"maildir:/srv/mail/../../etc":       SkipLocation,
		"maildir:":                          SkipLocation,
		"maildir:/srv/vmail/%d/%n":          SkipLocation,
		// Dovecot expands a userdb mail field later; CSM cannot tell
		// where a conditional puts anything.
		"maildir:~/Maildir:INDEX=%{IF;%d;eq;example.com;/a;/b}": SkipLocation,
		"maildir:~/Maildir:CONTROL=%L{if;%n;eq;x;~/c;~/d}":      SkipLocation,
	} {
		h := newHost(t, "alice@example.com")
		h.set("alice@example.com", 4, mail)
		snap, err := h.snapshot()
		if err != nil || snap.Mailboxes != nil || !reflect.DeepEqual(reasons(snap), map[string]string{"alice@example.com": reason}) {
			t.Errorf("mail %q: snapshot %+v, err %v", mail, snap, err)
		}
	}
}

// doveadm prints nothing, and still exits 0, for a user whose %{if} fails
// to expand, so a lookup whose template holds one cannot vouch for one
// record per user. A global or namespace location with %{if} is never
// looked up: every user is skipped as location, present but not watched.
func TestSnapshotConditionalLocationSkipsEveryMailbox(t *testing.T) {
	for _, c := range []struct{ from, to string }{
		{"mail_location = maildir:~/Maildir\n", "mail_location = maildir:~/Maildir:INDEX=%{if;%d;eq;example.com;/var/idx;/srv/idx}\n"},
		{"mail_location = maildir:~/Maildir\n", "mail_location = maildir:~/Maildir:CONTROL=%L{IF;%n;gt;5;~/c;~/d}\n"},
		{"  location = \n  mailbox \"Courrier", "  location = maildir:~/Maildir:INDEX=%{If;%u;=~;^a;/a;/b}\n  mailbox \"Courrier"},
	} {
		h := newHost(t, "alice@example.com", "bob@example.com", "dave")
		h.edit(c.from, c.to)
		snap, err := h.snapshot()
		want := map[string]string{"alice@example.com": SkipLocation, "bob@example.com": SkipLocation, "dave": SkipLocation}
		if err != nil || !snap.Complete || snap.Mailboxes != nil || !reflect.DeepEqual(reasons(snap), want) {
			t.Errorf("%s: snapshot %+v, err %v", c.to, snap, err)
		}
		if h.batches != nil || h.listings != 2 {
			t.Errorf("%s: lookups %q, %d listings", c.to, h.batches, h.listings)
		}
	}
}

func TestSnapshotHarmlessLocationParameters(t *testing.T) {
	h := newHost(t, "alice@example.com")
	h.set("alice@example.com", 4, "maildir:~/Maildir:INBOX=~/Maildir:INDEX=/var/idx/%u:CONTROL=~/ctl:LAYOUT=maildir++")
	snap, err := h.snapshot()
	if err != nil || len(snap.Mailboxes) != 1 || snap.Mailboxes[0].Junk[1] != "/srv/vmail/example.com/alice/Maildir/.Junk" {
		t.Fatalf("snapshot %+v, err %v", snap, err)
	}
}

// A5: on 2.3 a userdb mail field stands in for a missing mail_location.
func TestSnapshotUserdbMailWithoutGlobalLocation(t *testing.T) {
	h := newHost(t, "alice@example.com", "bob@example.com")
	h.edit("mail_location = maildir:~/Maildir\n", "")
	snap, err := h.snapshot()
	if err != nil || len(snap.Mailboxes) != 1 || snap.Mailboxes[0].Junk[1] != "/srv/vmail/example.com/bob/Mail/.Junk" ||
		!reflect.DeepEqual(reasons(snap), map[string]string{"alice@example.com": SkipDriver}) {
		t.Fatalf("snapshot %+v, err %v", snap, err)
	}
}

// Mailbox names are relative to their namespace: the prefix never reaches
// the disk and the separator becomes Maildir++'s dot.
func TestSnapshotNamespacePrefixAndSeparator(t *testing.T) {
	for _, c := range []struct{ prefix, sep, box, want string }{
		{"INBOX.", ".", "Junk", ".Junk"},
		{"INBOX.", ".", "Spam.Sub", ".Spam.Sub"},
		{"", "/", "Spam/Sub", ".Spam.Sub"},
		{"INBOX/", "/", "Junk", ".Junk"},
		{"", "", "Spam.Sub", ".Spam.Sub"},
	} {
		h := newHost(t, "alice@example.com")
		ns := "  prefix = " + c.prefix + "\n"
		if c.sep != "" {
			ns += "  separator = " + c.sep + "\n"
		}
		h.edit("  prefix = INBOX.\n  separator = .\n", ns)
		h.edit("  mailbox Junk {\n    auto", "  mailbox "+c.box+" {\n    auto")
		snap, err := h.snapshot()
		want := "/srv/vmail/example.com/alice/Maildir/" + c.want
		if err != nil || len(snap.Mailboxes) != 1 || len(snap.Mailboxes[0].Junk) != 3 || !slices.Contains(snap.Mailboxes[0].Junk, want) {
			t.Errorf("%+v: snapshot %+v, err %v", c, snap, err)
		}
	}
}

func TestSnapshotTwoJunkMailboxes(t *testing.T) {
	h := newHost(t, "alice@example.com")
	h.edit("special_use = \\Sent", "special_use = \\Junk")
	snap, err := h.snapshot()
	if err != nil || len(snap.Mailboxes) != 1 || len(snap.Mailboxes[0].Junk) != 4 ||
		!slices.Contains(snap.Mailboxes[0].Junk, "/srv/vmail/example.com/alice/Maildir/.Sent") {
		t.Fatalf("snapshot %+v, err %v", snap, err)
	}
}

func TestSnapshotNoJunkMailbox(t *testing.T) {
	h := newHost(t, "alice@example.com")
	h.edit("special_use = \\Junk", "special_use = \\Trash")
	snap, err := h.snapshot()
	if err != nil || !snap.Complete || snap.Mailboxes != nil || !reflect.DeepEqual(reasons(snap), map[string]string{"alice@example.com": SkipNoJunk}) {
		t.Fatalf("snapshot %+v, err %v", snap, err)
	}
}

func TestSnapshotSharedNamespaceJunkIsNotWatched(t *testing.T) {
	// The captured shared namespace has a \Junk mailbox; the inbox one has
	// none left, so nothing may be watched.
	h := newHost(t, "alice@example.com")
	h.edit("auto = create\n    special_use = \\Junk", "auto = create\n    special_use = \\Trash")
	snap, err := h.snapshot()
	if err != nil || snap.Mailboxes != nil || !reflect.DeepEqual(reasons(snap), map[string]string{"alice@example.com": SkipNoJunk}) {
		t.Fatalf("snapshot %+v, err %v", snap, err)
	}
}

func TestSnapshotListingFailures(t *testing.T) {
	for name, mutate := range map[string]func(*host){
		"exit 1":       func(h *host) { h.listErr = exitError(h.t, 1, "Fatal: something\n") },
		"start":        func(h *host) { h.listErr = exec.ErrNotFound },
		"timeout":      func(h *host) { h.listErr = context.DeadlineExceeded },
		"empty":        func(h *host) { h.list = "" },
		"blank lines":  func(h *host) { h.list = "\n\n" },
		"over bound":   func(h *host) { h.listOut = bytes.Repeat([]byte("a"), MaxListBytes+1) },
		"too many":     func(h *host) { h.listOut = manyUsers(MaxMailboxes + 1) },
		"final change": func(h *host) { h.final = "alice@example.com\nnew@example.com\n" },
		"final empty":  func(h *host) { h.final = "\n" },
	} {
		h := newHost(t, "alice@example.com")
		mutate(h)
		snap, err := h.snapshot()
		if err == nil || errors.Is(err, ErrCannotIterate) || !reflect.DeepEqual(snap, Snapshot{}) {
			t.Errorf("%s: snapshot %+v, err %v", name, snap, err)
		}
	}
}

func manyUsers(n int) []byte {
	var b bytes.Buffer
	for i := range n {
		fmt.Fprintf(&b, "u%d@example.com\n", i)
	}
	return b.Bytes()
}

func TestSnapshotDetailFailures(t *testing.T) {
	line := func(f ...string) []byte { return []byte(strings.Join(f, "\t") + "\n") }
	// rec is a well-formed record: it ends with its user again.
	rec := func(f ...string) []byte { return line(append(f, f[0])...) }
	for name, mutate := range map[string]func(*host){
		"timeout":    func(h *host) { h.detailErr = context.DeadlineExceeded },
		"start":      func(h *host) { h.detailErr = exec.ErrNotFound },
		"exit 1":     func(h *host) { h.detailExit = 1 },
		"exit 89":    func(h *host) { h.detailExit = 89 },
		"exit 64":    func(h *host) { h.detailErr = exitError(h.t, 64, "doveadm user [-a <userdb socket path>]\n") },
		"killed":     func(h *host) { h.detailErr = shellError(h.t, "kill -9 $$", "") },
		"over bound": func(h *host) { h.detailOut = bytes.Repeat([]byte("\n"), MaxListBytes+1) },
		"extra field": func(h *host) {
			h.detailOut = rec("alice@example.com", "1000", "1000", "/h", "", "", "maildir:~/M", "x")
		},
		"short line": func(h *host) { h.detailOut = line("alice@example.com", "1000", "1000") },
		"no trailer": func(h *host) { h.detailOut = line("alice@example.com", "1000", "1000", "/h", "", "", "maildir:~/M") },
		"wrong trailer": func(h *host) {
			h.detailOut = line("alice@example.com", "1000", "1000", "/h", "", "", "maildir:~/M", "bob@example.com")
		},
		"other user": func(h *host) { h.detailOut = rec("mallory@example.com", "1000", "1000", "/h", "", "", "maildir:~/M") },
		"duplicate": func(h *host) {
			h.detailOut = append(rec("alice@example.com", "1000", "1000", "/h", "", "", "maildir:~/M"), rec("alice@example.com", "1000", "1000", "/h", "", "", "maildir:~/M")...)
		},
		"control byte": func(h *host) { h.detailOut = rec("alice@example.com", "1000", "1000", "/h\r", "", "", "maildir:~/M") },
		"control home": func(h *host) { h.set("alice@example.com", 3, "/srv/vmail/a\x01b") },
		"bad uid":      func(h *host) { h.detailOut = rec("alice@example.com", "vmail", "1000", "/h", "", "", "maildir:~/M") },
		"negative uid": func(h *host) { h.detailOut = rec("alice@example.com", "-1", "1000", "/h", "", "", "maildir:~/M") },
		"wide uid": func(h *host) {
			h.detailOut = rec("alice@example.com", "4294967296", "1000", "/h", "", "", "maildir:~/M")
		},
		"missing": func(h *host) { h.detailOut = []byte("\n") },
	} {
		h := newHost(t, "alice@example.com")
		mutate(h)
		snap, err := h.snapshot()
		if err == nil || !reflect.DeepEqual(snap, Snapshot{}) {
			t.Errorf("%s: snapshot %+v, err %v", name, snap, err)
		}
	}
}

// doveadm exits EX_NOUSER or EX_TEMPFAIL when it could not look up some
// users and printed the others. Each printed record is then confirmed by a
// lookup of that user alone.
func TestSnapshotLookupFailureSkipsOnlyThatUser(t *testing.T) {
	for _, code := range []int{67, 75} {
		h := newHost(t, "alice@example.com", "ghost@example.com", "bob@example.com")
		h.missingExit = code
		snap, err := h.snapshot()
		if err != nil || !snap.Complete || len(snap.Mailboxes) != 2 ||
			!reflect.DeepEqual(reasons(snap), map[string]string{"ghost@example.com": SkipLookupFailed}) {
			t.Errorf("exit %d: snapshot %+v, err %v", code, snap, err)
		}
		want := [][]string{{"alice@example.com", "bob@example.com", "ghost@example.com"}, {"alice@example.com"}, {"bob@example.com"}}
		if !reflect.DeepEqual(h.batches, want) {
			t.Errorf("exit %d: lookups %q, want %q", code, h.batches, want)
		}
	}
}

// recLine is a well-formed lookup record: it ends with its user again.
func recLine(f ...string) string {
	return strings.Join(append(f, f[0]), "\t") + "\n"
}

// A lookup that exits 0 holds one record per user, in request order, each
// naming its user exactly as requested.
func TestSnapshotExitZeroLookupIsStrict(t *testing.T) {
	alice := []string{"alice@example.com", "1000", "1000", "/srv/a", "", "", "maildir:~/Maildir"}
	bob := []string{"bob@example.com", "1000", "1000", "/srv/b", "", "", "maildir:~/Maildir"}
	upper := append([]string{"ALICE@example.com"}, alice[1:]...)
	for name, out := range map[string]string{
		"order":   recLine(bob...) + "\n" + recLine(alice...),
		"case":    recLine(upper...) + "\n" + recLine(bob...),
		"one":     recLine(alice...),
		"blank":   "\n\n",
		"twice":   recLine(alice...) + "\n" + recLine(alice...) + "\n" + recLine(bob...),
		"surplus": recLine(alice...) + "\n" + recLine(bob...) + "\n" + recLine(append([]string{"carol@example.net"}, alice[1:]...)...),
	} {
		h := newHost(t, "alice@example.com", "bob@example.com")
		h.detailOut = []byte(out)
		snap, err := h.snapshot()
		if err == nil || !reflect.DeepEqual(snap, Snapshot{}) {
			t.Errorf("%s: snapshot %+v, err %v", name, snap, err)
		}
	}
}

// A record that a failed batch printed for a user whose own lookup does not
// confirm it fails the snapshot.
func TestSnapshotUnconfirmedRecordFailsSnapshot(t *testing.T) {
	ghost := recLine("ghost@example.com", "1001", "1001", "/srv/vmail/example.com/victim", "", "", "maildir:~/Maildir")
	alice := recLine("alice@example.com", "1000", "1000", "/srv/a", "", "", "maildir:~/Maildir")
	for name, single := range map[string]func(h *host, user string) ([]byte, error){
		"unknown alone": func(h *host, user string) ([]byte, error) {
			if user == "ghost@example.com" {
				return nil, exitError(h.t, 67, "")
			}
			return []byte(alice), nil
		},
		"tempfail alone": func(h *host, user string) ([]byte, error) {
			if user == "ghost@example.com" {
				return []byte(ghost), exitError(h.t, 75, "")
			}
			return []byte(alice), nil
		},
		"two records alone": func(h *host, user string) ([]byte, error) {
			return []byte(alice + "\n" + ghost), nil
		},
		"nothing alone": func(h *host, user string) ([]byte, error) {
			return nil, nil
		},
	} {
		h := newHost(t, "alice@example.com", "ghost@example.com")
		run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if len(args) > 4 && args[1] == "-e" {
				if names := args[4:]; len(names) == 1 {
					return single(h, names[0])
				}
				return []byte(alice + "\n" + ghost), exitError(h.t, 67, "")
			}
			return h.run(ctx, name, args...)
		}
		snap, err := Dovecot{Run: run}.Snapshot(context.Background())
		if err == nil || !reflect.DeepEqual(snap, Snapshot{}) {
			t.Errorf("%s: snapshot %+v, err %v", name, snap, err)
		}
	}
}

// %u is the name after lookup, which a userdb user field can rename to text
// holding tabs. That moves both anchors of a record; with a newline in
// another field, lines pass for records of ghost and zed, listed but
// unknown to doveadm.
const (
	attacker = "attacker@example.com"
	renamed  = attacker + "\t1\t1\tzed@example.com"
	victim   = "/srv/vmail/example.com/victim"
)

// forged is the attacker's lookup output: a home carrying a ghost record.
var forged = strings.Join([]string{renamed, "1000", "1000",
	"x\t" + attacker + "\nghost@example.com\t1001\t1001\t" + victim + "\t\t\tmaildir:~/Maildir\tghost@example.com\nzed@example.com",
	"1", "1", "maildir:~/Maildir", renamed}, "\t") + "\n"

// forgedPlugins needs only the user and mail_plugins fields, with one
// namespace location.
var forgedPlugins = strings.Join([]string{renamed, "1000", "1000", "/srv/vmail/example.com/attacker", "",
	attacker + "\nghost@example.com\t1001\t1001\t" + victim + "\t\t\tmaildir:~/Maildir\tmaildir:/srv/archive/x\tghost@example.com\nzed@example.com\t1\t1",
	"maildir:~/Maildir", "maildir:/srv/archive/x", renamed}, "\t") + "\n"

func TestSnapshotRenamedUserCannotForgeRecords(t *testing.T) {
	realGhost := recLine("ghost@example.com", "1001", "1001", victim, "", "", "maildir:~/Maildir")
	realZed := recLine("zed@example.com", "1002", "1002", "/srv/vmail/example.com/zed", "", "", "maildir:~/Maildir")
	for _, c := range []struct {
		name, batch, alone string
		exit               int
		namespaceLocation  bool
	}{
		{"failed batch", forged + "\n\n", forged, 67, false},
		{"failed batch, user and plugins only", forgedPlugins + "\n\n", forgedPlugins, 67, true},
		{"tempfail batch", forged + "\n\n", forged, 75, false},
		{"whole batch", forged + "\n" + realGhost + "\n" + realZed, forged, 0, false},
	} {
		h := newHost(t, attacker, "ghost@example.com", "zed@example.com")
		if c.namespaceLocation {
			h.edit("  location = \n  mailbox \"Courrier", "  location = maildir:/srv/archive/x\n  mailbox \"Courrier")
		}
		run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if len(args) > 4 && args[1] == "-e" {
				names := args[4:]
				switch {
				case len(names) > 1 && c.exit != 0:
					return []byte(c.batch), exitError(h.t, c.exit, "")
				case len(names) > 1:
					return []byte(c.batch), nil
				case names[0] == attacker:
					// The attacker's own lookup succeeds with the same text.
					return []byte(c.alone), nil
				}
				return nil, exitError(h.t, 67, "")
			}
			return h.run(ctx, name, args...)
		}
		snap, err := Dovecot{Run: run}.Snapshot(context.Background())
		if err == nil || snap.Complete || slices.ContainsFunc(snap.Mailboxes, func(m DovecotMailbox) bool { return m.User != attacker }) {
			t.Errorf("%s: snapshot %+v, err %v", c.name, snap, err)
		}
	}
}

// A newline and tabs in one user's field must not make a record for another
// user of the batch, whatever the attacker knows about the template.
func TestSnapshotFieldCannotForgeAnotherRecord(t *testing.T) {
	const alice = "/srv/vmail/example.com/alice"
	for _, home := range []string{
		alice + "\t\t\tmaildir:" + alice + "/Maildir\nghost@example.com\t1000\t1000\t" + alice,
		// Both fragments are whole records; only the trailer tells the
		// second one, which ends with alice, from ghost's.
		alice + "\t\t\tmaildir:~/Maildir\talice@example.com\nghost@example.com\t1000\t1000\t" + alice,
		alice + "\t\t\tmaildir:~/Maildir\talice@example.com\nghost@example.com\t1000\t1000\t" + alice + "\t\t\tmaildir:~/Maildir\tghost@example.com\n" + alice,
		alice + "\t\t\tmaildir:~/Maildir\talice@example.com\nghost@example.com\t1000\t1000\t" + alice + "\t\t\tmaildir:~/Maildir\tghost@example.com\nalice@example.com\t1000\t1000\t" + alice,
	} {
		h := newHost(t, "alice@example.com", "ghost@example.com")
		h.set("alice@example.com", 3, home)
		snap, err := h.snapshot()
		if err == nil || snap.Complete || slices.ContainsFunc(snap.Mailboxes, func(m DovecotMailbox) bool { return m.User == "ghost@example.com" }) {
			t.Errorf("home %q: snapshot %+v, err %v", home, snap, err)
		}
	}
}

// A lookup batch cut off by its deadline is an error even when the command
// reports a plain exit, so its missing users never become skips.
func TestSnapshotTimedOutLookupIsAnError(t *testing.T) {
	for name, exit := range map[string]func(*host) error{
		"killed":  func(*host) error { return &exec.ExitError{} },
		"exit 67": func(h *host) error { return exitError(h.t, 67, "") },
	} {
		h := newHost(t, "alice@example.com", "bob@example.com")
		ctx, cancel := context.WithCancel(context.Background())
		run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
			out, err := h.run(ctx, name, args...)
			if len(args) > 1 && args[1] == "-e" {
				cancel()
				return out[:bytes.IndexByte(out, '\n')+1], exit(h)
			}
			return out, err
		}
		snap, err := Dovecot{Run: run}.Snapshot(ctx)
		if err == nil || !reflect.DeepEqual(snap, Snapshot{}) {
			t.Errorf("%s: snapshot %+v, err %v", name, snap, err)
		}
		cancel()
	}
}

func TestSnapshotNamesAreValidatedBeforeLookup(t *testing.T) {
	h := newHost(t, "alice@example.com", "a*@example.com", "b?c@example.com", "a b@example.com",
		"x@localhost", "x@exa_mple.com", "a@b@example.com", strings.Repeat("a", 65)+"@example.com", "ALICE@EXAMPLE.COM")
	snap, err := h.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(h.batches) != 1 || !slices.Equal(h.batches[0], []string{"ALICE@EXAMPLE.COM"}) {
		t.Fatalf("looked up %q", h.batches)
	}
	if len(snap.Skips) != 7 || slices.ContainsFunc(snap.Skips, func(s Skip) bool { return s != Skip{Reason: SkipInvalidName} }) {
		t.Fatalf("skips %+v", snap.Skips)
	}
	if len(snap.Mailboxes) != 1 || snap.Mailboxes[0].User != "alice@example.com" || snap.Mailboxes[0].Domain != "example.com" {
		t.Fatalf("mailboxes %+v", snap.Mailboxes)
	}
}

func TestSnapshotLooksUpInBatches(t *testing.T) {
	var users []string
	for i := range 2*batchSize + 1 {
		users = append(users, fmt.Sprintf("u%03d@example.com", i))
	}
	h := newHost(t, users...)
	for _, u := range users {
		h.fields[u] = u + "\t1000\t1000\t/srv/vmail/" + u + "\t\t"
	}
	snap, err := h.snapshot()
	if err != nil || len(snap.Mailboxes) != len(users) || len(h.batches) != 3 || len(h.batches[0]) != batchSize || len(h.batches[2]) != 1 {
		t.Fatalf("%d mailboxes, %d batches, err %v", len(snap.Mailboxes), len(h.batches), err)
	}
	if h.listings != 2 {
		t.Fatalf("%d listings, want the listing and the final one", h.listings)
	}
}

func TestParseConfigRejectsUnbalancedSections(t *testing.T) {
	for _, conf := range []string{"namespace inbox {\n", "}\n", "a = b\n}\n", "namespace inbox {\n  mailbox Junk {\n  }\n", "garbage\n"} {
		if _, err := parseConfig([]byte(conf)); err == nil {
			t.Errorf("%q parsed", conf)
		}
	}
}

func TestFolderDirNames(t *testing.T) {
	for _, c := range []struct {
		name, sep string
		utf8      bool
		want      string
	}{
		{"Junk", ".", false, ".Junk"},
		{"Spam.Sub", ".", false, ".Spam.Sub"},
		{"Spam/Sub", "/", false, ".Spam.Sub"},
		{"Courrier indésirable", ".", false, ".Courrier ind&AOk-sirable"},
		{"Courrier indésirable", ".", true, ".Courrier indésirable"},
		{"Spam & Co", ".", false, ".Spam &- Co"},
		{"a.b", "/", false, ""},
		{"a/b", ".", false, ""},
		{"../x", ".", false, ""},
		{"..", "/", false, ""},
		{"a..b", ".", false, ""},
		{".Junk", ".", false, ""},
		{"Junk.", ".", false, ""},
		{"", ".", false, ""},
		{"INBOX", ".", false, ""},
		{"inbox", ".", false, ""},
		{"a\x01b", ".", false, ""},
		{"a\u0085b", ".", true, ""},
		{"Junk", "", false, ""},
		{"Junk", "::", false, ""},
		{"\xff", ".", true, ""},
	} {
		got, ok := folderDir(c.name, c.sep, c.utf8)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("folderDir(%q, %q, %v) = %q, %v; want %q", c.name, c.sep, c.utf8, got, ok, c.want)
		}
	}
}

// RFC 3501 section 5.1.3 and Dovecot's own encoding of the captured names.
func TestModifiedUTF7(t *testing.T) {
	for in, want := range map[string]string{
		"Junk":               "Junk",
		"&":                  "&-",
		"indésirable":        "ind&AOk-sirable",
		"~peter/mail/台北/日本語": "~peter/mail/&U,BTFw-/&ZeVnLIqe-",
		"\U0001F600":         "&2D3eAA-",
		"a\tb":               "a&AAk-b",
	} {
		if got := mutf7(in); got != want {
			t.Errorf("mutf7(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunCommandBoundsOutput(t *testing.T) {
	out, err := runCommand(context.Background(), "sh", "-c", fmt.Sprintf("head -c %d /dev/zero", MaxListBytes+1))
	if err == nil || len(out) > MaxListBytes {
		t.Fatalf("%d bytes, err %v", len(out), err)
	}
	out, err = runCommand(context.Background(), "sh", "-c", fmt.Sprintf("head -c %d /dev/zero", MaxListBytes))
	if err != nil || len(out) != MaxListBytes {
		t.Fatalf("%d bytes at the bound, err %v", len(out), err)
	}
}

func TestRunCommandKeepsStderrOnExit(t *testing.T) {
	out, err := runCommand(context.Background(), "sh", "-c", "echo partial; echo 'User listing returned failure' >&2; exit 75")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 75 || string(exit.Stderr) != "User listing returned failure\n" || string(out) != "partial\n" {
		t.Fatalf("out %q, err %v", out, err)
	}
}

func TestRunCommandStopsAtDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	// The child keeps the pipe open; the process group is killed with it.
	_, err := runCommand(ctx, "sh", "-c", "sleep 30 & sleep 30")
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
}

func TestValidDomainRules(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	// 63+1+63+1+63+1+61 = 253 bytes.
	d253 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 61)
	for in, want := range map[string]bool{
		"example.com":       true,
		"Example.COM":       true,
		"a-b.example.net":   true,
		"xn--bcher-kva.com": true,
		d253:                true,
		d253 + "c":          false,
		label63 + ".com":    true,
		label63 + "a.com":   false,
		"-a.example.com":    false,
		"a-.example.com":    false,
		"a..example.com":    false,
		".example.com":      false,
		"example.com.":      false,
		"":                  false,
		"localhost":         false,
		"virtual":           false,
		"bücher.com":        false,
		"a_b.example.com":   false,
		"a b.example.com":   false,
		"../example.com":    false,
		"example.com/x":     false,
		"exa\x00mple.com":   false,
	} {
		if got := ValidDomain(in); got != want {
			t.Errorf("ValidDomain(%q) = %v", in, got)
		}
	}
}

func TestValidMailboxRules(t *testing.T) {
	for in, want := range map[string]bool{
		"user":                  true,
		"first.last":            true,
		"a+tag":                 true,
		"o'brien":               true,
		"x_y-z":                 true,
		strings.Repeat("a", 64): true,
		strings.Repeat("a", 65): false,
		".user":                 false,
		"user.":                 false,
		"a..b":                  false,
		"":                      false,
		".":                     false,
		"..":                    false,
		"a/b":                   false,
		"a\\b":                  false,
		"a b":                   false,
		"a\tb":                  false,
		"a\x01b":                false,
		"\"quoted\"":            false,
		"a\"b":                  false,
		"müller":                false,
		"a@b":                   false,
		"a,b":                   false,
	} {
		if got := ValidMailbox(in); got != want {
			t.Errorf("ValidMailbox(%q) = %v", in, got)
		}
	}
}
