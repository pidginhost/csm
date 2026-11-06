//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

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
// registry and home roots. exampleco hosts domains.
func liveMailboxSourceOver(accounts learnwatch.Source, domains ...string) *liveMailboxSource {
	hosted := map[string]string{}
	for _, domain := range domains {
		hosted[domain] = "exampleco"
	}
	src := newLiveMailboxSource(accounts).(*liveMailboxSource)
	src.inventory = func() (checks.HostingSnapshot, error) {
		return checks.HostingSnapshot{Accounts: []string{"exampleco"}, Domains: hosted}, nil
	}
	return src
}

func TestLiveMailboxSourceReadsPasswdLists(t *testing.T) {
	home, accounts := mailboxHome(t, "exampleco")
	writeMailboxList(t, home, "example.com", "sales:x:1001:1001::/mail/sales:/bin/false\ninfo:x:1001:1001::/mail/info:/bin/false\n")
	src := liveMailboxSourceOver(accounts, "example.com", "example.net")
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

// Login names are compared in lower case, so a mixed-case record must still
// answer for the real mailbox. Folding can reorder a list and merge entries;
// lookups need it sorted and distinct.
func TestLiveMailboxSourceFoldsCase(t *testing.T) {
	home, accounts := mailboxHome(t, "exampleco")
	writeMailboxList(t, home, "example.com", "Zed:x:1001:1001::/m:/bin/false\nalpha:x:1001:1001::/m:/bin/false\nInfo:x:1001:1001::/m:/bin/false\ninfo:x:1001:1001::/m:/bin/false\nSALES:x:1001:1001::/m:/bin/false\nINFO:x:1001:1001::/m:/bin/false\n")
	writeMailboxList(t, home, "Shop.Example.ORG", "Orders:x:1001:1001::/m:/bin/false\n")
	src := liveMailboxSourceOver(accounts, "example.com", "shop.example.org")
	r := newCPanelMailboxResolver(src, time.Now)
	for _, name := range []string{"alpha@example.com", "info@example.com", "sales@example.com", "zed@example.com"} {
		if got, want := r.Resolve(name), (sprayMailbox{name: name, exist: mailboxExists}); got != want {
			t.Errorf("Resolve(%q) = %+v, want %+v", name, got, want)
		}
	}
	if got := r.Resolve("nosuch@example.com"); got.exist != mailboxMissing {
		t.Errorf("nosuch@example.com exist = %v, want Missing", got.exist)
	}
	// Known limit: only the hosted domain's own spelling is read and ~/etc is
	// not listed, so a directory spelled another way is not seen.
	if got := r.Resolve("orders@shop.example.org"); got.exist != mailboxMissing {
		t.Errorf("orders@shop.example.org exist = %v, want Missing", got.exist)
	}
	want := map[string][]string{"example.com": {"alpha", "info", "sales", "zed"}}
	lists, complete, err := src.Mailboxes("exampleco")
	if err != nil || !complete || !reflect.DeepEqual(lists, want) {
		t.Fatalf("Mailboxes = %v, %v, %v, want %v, complete", lists, complete, err, want)
	}
}

// A hosted domain that is a link is a layout CSM cannot read. Answering from
// an empty list would call its real mailboxes missing.
func TestLiveMailboxSourceLinkedDomainIsUnknown(t *testing.T) {
	home, accounts := mailboxHome(t, "exampleco")
	writeMailboxList(t, home, "example.com", "info:x:1001:1001::/m:/bin/false\n")
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "passwd"), []byte("victim:x:1001:1001::/m:/bin/false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, "etc", "example.org")); err != nil {
		t.Fatal(err)
	}
	src := liveMailboxSourceOver(accounts, "example.com", "example.org")
	if _, err := src.Inventory(); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"example.com": {"info"}}
	lists, complete, err := src.Mailboxes("exampleco")
	if err != nil || complete || !reflect.DeepEqual(lists, want) {
		t.Fatalf("Mailboxes = %v, %v, %v, want %v, incomplete", lists, complete, err, want)
	}
	r := newCPanelMailboxResolver(src, time.Now)
	for _, name := range []string{"victim@example.org", "nosuch@example.org"} {
		if got, want := r.Resolve(name), (sprayMailbox{name: name}); got != want {
			t.Errorf("Resolve(%q) = %+v, want %+v", name, got, want)
		}
	}
}

// Stock cPanel directories under ~/etc are not domains and must not switch the
// lookup off for the account.
func TestLiveMailboxSourceIgnoresDirsThatAreNotHosted(t *testing.T) {
	home, accounts := mailboxHome(t, "exampleco")
	writeMailboxList(t, home, "example.com", "info:x:1001:1001::/m:/bin/false\n")
	writeMailboxList(t, home, "unhosted.example.net", "../x:x:1001:1001::/m:/bin/false\n")
	if err := os.Mkdir(filepath.Join(home, "etc", "webdav"), 0o700); err != nil {
		t.Fatal(err)
	}
	src := liveMailboxSourceOver(accounts, "example.com")
	if _, err := src.Inventory(); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"example.com": {"info"}}
	lists, complete, err := src.Mailboxes("exampleco")
	if err != nil || !complete || !reflect.DeepEqual(lists, want) {
		t.Fatalf("Mailboxes = %v, %v, %v, want %v, complete", lists, complete, err, want)
	}
	r := newCPanelMailboxResolver(src, time.Now)
	if got := r.Resolve("nosuch@example.com"); got.exist != mailboxMissing {
		t.Errorf("nosuch@example.com exist = %v, want Missing", got.exist)
	}
	if got := r.Resolve("info@example.com"); got.exist != mailboxExists {
		t.Errorf("info@example.com exist = %v, want Exists", got.exist)
	}
}

// Domain names reach the reader only from the snapshot, only for their owner,
// and only when they are valid.
func TestLiveMailboxSourceReadsOnlyOwnValidDomains(t *testing.T) {
	home, accounts := mailboxHome(t, "exampleco")
	writeMailboxList(t, home, "example.com", "info:x:1001:1001::/m:/bin/false\n")
	writeMailboxList(t, home, "other.example.org", "foreign:x:1001:1001::/m:/bin/false\n")
	writeMailboxList(t, home, "a/b.example.com", "nested:x:1001:1001::/m:/bin/false\n")
	src := liveMailboxSourceOver(accounts)
	src.inventory = func() (checks.HostingSnapshot, error) {
		return checks.HostingSnapshot{
			Accounts: []string{"exampleco", "otherco"},
			Domains: map[string]string{
				"example.com":       "exampleco",
				"other.example.org": "otherco",
				"a/b.example.com":   "exampleco",
			},
		}, nil
	}
	if _, err := src.Inventory(); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"example.com": {"info"}}
	lists, complete, err := src.Mailboxes("exampleco")
	if err != nil || !complete || !reflect.DeepEqual(lists, want) {
		t.Fatalf("Mailboxes = %v, %v, %v, want %v, complete", lists, complete, err, want)
	}
}

func TestLiveMailboxSourceHomeWithoutLists(t *testing.T) {
	_, accounts := mailboxHome(t, "exampleco")
	src := liveMailboxSourceOver(accounts, "example.com")
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
	src := liveMailboxSourceOver(accounts, "example.com")
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
