package learnwatch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/dovecot"
	"github.com/pidginhost/csm/internal/store"
)

func TestReporterIDDeterministicAndRange(t *testing.T) {
	seen := map[int]string{}
	for i := range 5000 {
		domain := fmt.Sprintf("d%d.example.com", i)
		id := ReporterID(antispam.ReporterDomain, domain, "")
		if again := ReporterID(antispam.ReporterDomain, domain, "x@"+domain); again != id {
			t.Fatalf("%s: %d then %d", domain, id, again)
		}
		if id < 1<<32 || id >= 1<<62 || id == -1 {
			t.Fatalf("%s: id %d out of range", domain, id)
		}
		if other, dup := seen[id]; dup {
			t.Fatalf("%s and %s share id %d", domain, other, id)
		}
		seen[id] = domain
	}
	box := ReporterID(antispam.ReporterMailbox, "example.com", "a@example.com")
	if box == ReporterID(antispam.ReporterMailbox, "example.com", "b@example.com") ||
		box == ReporterID(antispam.ReporterDomain, "example.com", "a@example.com") || box < 1<<32 {
		t.Fatalf("mailbox ids do not split: %d", box)
	}
	// Pinned: the id must survive restarts, releases and ResetLearnWatch.
	// The second hash has bit 32 clear and a top bit set.
	for _, c := range []struct {
		mode, domain, mailbox string
		want                  int
	}{
		{antispam.ReporterDomain, "example.com", "", 0x0a75b1b35db8ea04},
		{antispam.ReporterMailbox, "example.com", "alice@example.com", 0x3cf558bbbd139f6f},
	} {
		if got := ReporterID(c.mode, c.domain, c.mailbox); got != c.want {
			t.Errorf("%s %s%s is %#x, want %#x", c.mode, c.domain, c.mailbox, got, c.want)
		}
	}
}

// Existing watcher state is keyed by an 8-byte big-endian UID; reporter
// ids keep that layout and sort before the meta and pending keys.
func TestUIDPrefixKeepsAccountKeys(t *testing.T) {
	k := FolderKey{UID: 1001, Domain: "example.com", Box: "info", Folder: ".spam"}
	if want := []byte("\x00\x00\x00\x00\x00\x00\x03\xe9\x00example.com\x00info\x00.spam"); !bytes.Equal(k.key(), want) {
		t.Fatalf("key %q", k.key())
	}
	id := ReporterID(antispam.ReporterDomain, "example.com", "")
	if p := uidPrefix(id); len(p) != 8 || p[0] >= cursorKey[0] {
		t.Fatalf("reporter prefix %x", p)
	}
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := NewState(db, func() time.Time { return t0 })
	var got int
	err = s.Update(func(tx StateTx) error { return tx.SetCursor(id) })
	if err == nil {
		err = s.View(func(tx StateTx) (e error) { got, e = tx.Cursor(); return e })
	}
	if err != nil || got != id {
		t.Fatalf("cursor %d, want %d, err %v", got, id, err)
	}
}

// The watcher's finding follows the pass's rule: a listing that fails on a
// userdb that can list users is an outage, in the registry read and in the
// removal recheck. Only a userdb that cannot list users is definite.
func TestPostfixListingFailureFinding(t *testing.T) {
	for userdb, reason := range map[string]string{
		"userdb {\n  args = /etc/dovecot/dovecot-sql.conf.ext\n  driver = sql\n}\n":            antispam.ReasonBackendUnavailable,
		"userdb {\n  args = uid=vmail gid=vmail home=/srv/vmail/%d/%n\n  driver = static\n}\n": antispam.ReasonUnsupported,
	} {
		run := func(_ context.Context, name string, args ...string) ([]byte, error) {
			switch strings.Join(append([]string{name}, args...), " ") {
			case "dovecot --version":
				return []byte("2.3.21 (47349e2482)\n"), nil
			case "doveconf -n":
				return []byte("mail_location = maildir:~/Maildir\n" + userdb), nil
			case "doveadm user *":
				var exit *exec.ExitError
				if err := exec.Command("sh", "-c", "exit 75").Run(); !errors.As(err, &exit) {
					t.Fatalf("exit 75: %v", err)
				}
				exit.Stderr = []byte("Error: auth-master: userdb list: User listing returned failure\nFatal: user listing failed\n")
				return nil, exit
			}
			t.Errorf("unexpected command %s %q", name, args)
			return nil, errors.New("unexpected command")
		}
		p := &Postfix{Dovecot: dovecot.Dovecot{Run: run}, Reporter: antispam.ReporterDomain}
		_, err := p.registry(context.Background())
		if got := antispam.DovecotProblem(err).Key; err == nil || got != reason {
			t.Errorf("%q: registry err %v gives %s, want %s", userdb, err, got, reason)
		}
		_, err = p.removed(context.Background(), nil, ReporterID(antispam.ReporterDomain, "example.com", ""))
		if got := antispam.DovecotProblem(err).Key; err == nil || got != antispam.ReasonBackendUnavailable {
			t.Errorf("%q: recheck err %v gives %s", userdb, err, got)
		}
	}
}
