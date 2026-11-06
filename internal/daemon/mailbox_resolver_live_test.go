//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pidginhost/csm/internal/antispam/learnwatch"
	"github.com/pidginhost/csm/internal/checks"
)

// mailboxHome is a home with the given account's non-root owner, and the
// source that names it.
func mailboxHome(t *testing.T, account string) (string, staticSource) {
	t.Helper()
	home := filepath.Join(t.TempDir(), account)
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	if uid == 0 {
		// Accounts refuses root; CI may run as root.
		uid = 1001
		if err := os.Chown(home, uid, uid); err != nil {
			t.Fatal(err)
		}
	}
	return home, staticSource{users: []string{account}, passwd: fmt.Sprintf("%s:x:%d:%d::%s:/bin/bash\n", account, uid, uid, home)}
}

func writeMailboxList(t *testing.T, home, domain, records string) {
	t.Helper()
	dir := filepath.Join(home, "etc", domain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "passwd"), []byte(records), 0o600); err != nil {
		t.Fatal(err)
	}
}

// liveMailboxSourceOver stubs the host inventory, which reads the host's own
// registry and home roots.
func liveMailboxSourceOver(accounts learnwatch.Source) *liveMailboxSource {
	src := newLiveMailboxSource(accounts).(*liveMailboxSource)
	src.inventory = func() (checks.HostingSnapshot, error) { return checks.HostingSnapshot{}, nil }
	return src
}

func TestLiveMailboxSourceReadsPasswdLists(t *testing.T) {
	home, accounts := mailboxHome(t, "exampleco")
	writeMailboxList(t, home, "example.com", "sales:x:1001:1001::/mail/sales:/bin/false\ninfo:x:1001:1001::/mail/info:/bin/false\n")
	src := liveMailboxSourceOver(accounts)
	if _, err := src.Inventory(); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"example.com": {"info", "sales"}}
	lists, complete, err := src.Mailboxes("exampleco")
	if err != nil || !complete || !reflect.DeepEqual(lists, want) {
		t.Fatalf("Mailboxes = %v, %v, %v, want %v, complete", lists, complete, err, want)
	}

	writeMailboxList(t, home, "example.net", "../x:x:1001:1001::/mail/x:/bin/false\n")
	lists, complete, err = src.Mailboxes("exampleco")
	if err != nil || complete || !reflect.DeepEqual(lists, want) {
		t.Fatalf("with an unsupported entry Mailboxes = %v, %v, %v, want %v, incomplete", lists, complete, err, want)
	}
}

func TestLiveMailboxSourceHomeWithoutLists(t *testing.T) {
	_, accounts := mailboxHome(t, "exampleco")
	src := liveMailboxSourceOver(accounts)
	if _, err := src.Inventory(); err != nil {
		t.Fatal(err)
	}
	lists, complete, err := src.Mailboxes("exampleco")
	if err != nil || !complete || len(lists) != 0 {
		t.Fatalf("Mailboxes = %v, %v, %v, want no lists, complete", lists, complete, err)
	}
}

func TestLiveMailboxSourceReadsOnlyInventoriedAccounts(t *testing.T) {
	home, accounts := mailboxHome(t, "exampleco")
	writeMailboxList(t, home, "example.com", "info:x:1001:1001::/mail/info:/bin/false\n")
	src := liveMailboxSourceOver(accounts)
	if _, _, err := src.Mailboxes("exampleco"); err == nil {
		t.Error("read an account before any Inventory")
	}
	if _, err := src.Inventory(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := src.Mailboxes("exampleco"); err != nil {
		t.Fatalf("inventoried account: %v", err)
	}
	if _, _, err := src.Mailboxes("../exampleco"); err == nil {
		t.Error("read a name outside the account list")
	}
	src.source = staticSource{}
	if _, err := src.Inventory(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := src.Mailboxes("exampleco"); err == nil {
		t.Error("read an account that left the registry")
	}
}

type failingAccountSource struct{ staticSource }

func (failingAccountSource) CPanelUsers() ([]string, error) {
	return nil, errors.New("registry unreadable")
}

func TestLiveMailboxSourceInventoryFailures(t *testing.T) {
	src := liveMailboxSourceOver(failingAccountSource{})
	if _, err := src.Inventory(); err == nil {
		t.Error("account list failure not reported")
	}
	failure := errors.New("inventory unreadable")
	src = liveMailboxSourceOver(staticSource{})
	src.inventory = func() (checks.HostingSnapshot, error) { return checks.HostingSnapshot{}, failure }
	if _, err := src.Inventory(); !errors.Is(err, failure) {
		t.Errorf("Inventory error = %v, want %v", err, failure)
	}
}

// The default source answers with the host's own inventory, whatever that is
// on the machine running the test.
func TestLiveMailboxSourceUsesHostingInventory(t *testing.T) {
	want, wantErr := checks.HostingInventory()
	got, err := newLiveMailboxSource(staticSource{}).Inventory()
	if !reflect.DeepEqual(got, want) || (err == nil) != (wantErr == nil) {
		t.Fatalf("Inventory = %+v, %v, want %+v, %v", got, err, want, wantErr)
	}
}
