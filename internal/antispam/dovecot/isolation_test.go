package dovecot

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestSnapshotTempfailPausesDiscovery(t *testing.T) {
	h := newHost(t, "alice@example.com", "unavailable@example.net")
	h.missingExit = exTempFail
	snap, err := h.snapshot()
	if err == nil || !reflect.DeepEqual(snap, Snapshot{}) {
		t.Fatalf("temporary user lookup failure accepted: snapshot %+v, err %v", snap, err)
	}
}

func TestAmbiguousUserListingCannotAuthorizeRemoval(t *testing.T) {
	for _, names := range [][]string{{"alice@example.com", "bad name"}, {"alice@example.com", "ALICE@example.com"}} {
		h := newHost(t, names...)
		if snap, err := h.snapshot(); err == nil || !reflect.DeepEqual(snap, Snapshot{}) {
			t.Errorf("ambiguous snapshot accepted: %+v, %v", snap, err)
		}
		if users, err := (Dovecot{Run: h.run}).Users(context.Background()); err == nil || users != nil {
			t.Errorf("ambiguous removal listing accepted: %q, %v", users, err)
		}
	}
}

func TestSnapshotUnresolvedPathHoldsSharedUID(t *testing.T) {
	h := newHost(t, "alice@example.com", "bob@example.com", "carol@example.net")
	h.set("bob@example.com", 4, "maildir:/srv/vmail/%d/%n")
	snap, err := h.snapshot()
	if err != nil || len(snap.Mailboxes) != 1 || snap.Mailboxes[0].User != "carol@example.net" || len(snap.Skips) != 2 {
		t.Fatalf("unresolved mail path did not protect its shared UID: %+v, %v", snap, err)
	}
}

func TestSnapshotReservesResolvedMailPaths(t *testing.T) {
	dir := t.TempDir()
	actual := filepath.Join(dir, "actual")
	if err := os.MkdirAll(filepath.Join(actual, "Maildir"), 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(actual, alias); err != nil {
		t.Fatal(err)
	}
	h := newHost(t, "alice@example.com", "bob@example.com", "carol@example.net")
	h.set("alice@example.com", 3, alias)
	h.set("bob@example.com", 4, "maildir:"+actual+"/Maildir")
	snap, err := h.snapshot()
	if err != nil || len(snap.Mailboxes) != 1 || snap.Mailboxes[0].User != "carol@example.net" || !slices.EqualFunc(snap.Skips, []string{"alice@example.com", "bob@example.com"}, func(s Skip, u string) bool { return s.User == u && s.Reason == SkipSharedPath }) {
		t.Fatalf("another user's symlinked mail path accepted as Junk: %+v, %v", snap, err)
	}
}

func TestSnapshotNoUserCannotHideTemporaryFailure(t *testing.T) {
	h := newHost(t, "alice@example.com", "unavailable@example.net")
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) == 5 && args[4] == "unavailable@example.net" {
			return nil, exitError(t, exTempFail, "")
		}
		return h.run(ctx, name, args...)
	}
	snap, err := (Dovecot{Run: run}).Snapshot(context.Background())
	if err == nil || !reflect.DeepEqual(snap, Snapshot{}) {
		t.Fatalf("batch no-user status hid a temporary lookup failure: %+v, %v", snap, err)
	}
}

func TestSnapshotReservesNamespacesWithoutJunk(t *testing.T) {
	h := newHost(t, "alice@example.com", "bob@example.com", "carol@example.net")
	h.conf += "namespace archive {\n  location = maildir:~/Archive\n  mailbox Sent {\n    special_use = \\Sent\n  }\n}\n"
	h.set("carol@example.net", 4, "maildir:/srv/vmail/example.com/alice/Archive")
	h.set("carol@example.net", 1, "1000")
	snap, err := h.snapshot()
	want := map[string]string{"alice@example.com": SkipSharedPath, "carol@example.net": SkipSharedPath}
	if err != nil || len(snap.Mailboxes) != 1 || snap.Mailboxes[0].User != "bob@example.com" || !reflect.DeepEqual(reasons(snap), want) {
		t.Fatalf("another user's archive accepted as Junk: snapshot %+v, err %v", snap, err)
	}
}
