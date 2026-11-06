package daemon

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

var _ mailboxResolver = (*cpanelMailboxResolver)(nil)

// fakeMailboxSource is not locked: the resolver serialises every call.
type fakeMailboxSource struct {
	snapshot       checks.HostingSnapshot
	lists          map[string]map[string][]string
	inventoryErr   error
	mailboxesErr   error
	incomplete     bool
	unreadable     map[string]bool
	inventoryCalls int
	mailboxCalls   []string
}

func (f *fakeMailboxSource) Inventory() (checks.HostingSnapshot, error) {
	f.inventoryCalls++
	return f.snapshot, f.inventoryErr
}

func (f *fakeMailboxSource) Mailboxes(account string) (map[string][]string, bool, error) {
	f.mailboxCalls = append(f.mailboxCalls, account)
	if f.unreadable[account] {
		return nil, false, errors.New("read failed")
	}
	return f.lists[account], !f.incomplete, f.mailboxesErr
}

func newFakeMailboxSource() *fakeMailboxSource {
	return &fakeMailboxSource{
		snapshot: checks.HostingSnapshot{
			Accounts:   []string{"exampleco"},
			Domains:    map[string]string{"example.com": "exampleco"},
			Unresolved: map[string]bool{"example.net": true},
		},
		lists: map[string]map[string][]string{"exampleco": {"example.com": {"info", "sales"}}},
	}
}

// mailboxResolverRows are looked up after normalising input. resolved is the
// answered name when it differs from the normalised input; hosted rows depend
// on the mailbox lists of example.com.
var mailboxResolverRows = []struct {
	input    string
	want     mailboxExistence
	resolved string
	hosted   bool
}{
	{input: "info@example.com", want: mailboxExists, hosted: true},
	{input: "Info@Example.COM.", want: mailboxExists, resolved: "info@example.com", hosted: true},
	{input: "exampleco@example.com", want: mailboxExists, hosted: true},
	{input: "exampleco@example.com.", want: mailboxExists, resolved: "exampleco@example.com", hosted: true},
	{input: "nosuch@example.com", want: mailboxMissing, hosted: true},
	{input: "nosuch@example.com.", want: mailboxMissing, hosted: true},
	{input: "nosuch@example.org", want: mailboxMissing},
	{input: "nosuch@example.org.", want: mailboxMissing},
	{input: "x@example.net", want: mailboxExistenceUnknown},
	{input: "x@example.net.", want: mailboxExistenceUnknown},
	{input: "x@example.com..", want: mailboxExistenceUnknown},
	{input: "exampleco", want: mailboxExists},
	{input: "exampleco.", want: mailboxMissing},
	{input: "admin", want: mailboxMissing},
	{input: "__cpanel__service__auth__x", want: mailboxExistenceUnknown},
	{input: "info+example.com", want: mailboxExistenceUnknown},
	{input: "info%example.com", want: mailboxExistenceUnknown},
	{input: "in+fo@example.com", want: mailboxExistenceUnknown, hosted: true},
	{input: "in%fo@example.com", want: mailboxExistenceUnknown, hosted: true},
	{input: "", want: mailboxExistenceUnknown},
}

func TestMailboxResolverExistence(t *testing.T) {
	r := newCPanelMailboxResolver(newFakeMailboxSource(), time.Now)
	for _, row := range mailboxResolverRows {
		name := normalizeSprayMailbox(row.input)
		want := sprayMailbox{name: name, exist: row.want}
		if row.resolved != "" {
			want.name = row.resolved
		}
		if got := r.Resolve(name); got != want {
			t.Errorf("Resolve(%q) = %+v, want %+v", name, got, want)
		}
	}
}

func TestMailboxResolverFailsUnknown(t *testing.T) {
	failure := errors.New("read failed")
	t.Run("inventory error", func(t *testing.T) {
		src := newFakeMailboxSource()
		src.inventoryErr = failure
		r := newCPanelMailboxResolver(src, time.Now)
		for _, row := range mailboxResolverRows {
			name := normalizeSprayMailbox(row.input)
			if got, want := r.Resolve(name), (sprayMailbox{name: name}); got != want {
				t.Errorf("Resolve(%q) = %+v, want %+v", name, got, want)
			}
		}
		if len(src.mailboxCalls) != 0 {
			t.Errorf("read mailbox lists with no snapshot: %v", src.mailboxCalls)
		}
	})
	for name, breakLists := range map[string]func(*fakeMailboxSource){
		"mailboxes error":  func(f *fakeMailboxSource) { f.mailboxesErr = failure },
		"incomplete lists": func(f *fakeMailboxSource) { f.incomplete = true },
	} {
		t.Run(name, func(t *testing.T) {
			src := newFakeMailboxSource()
			breakLists(src)
			r := newCPanelMailboxResolver(src, time.Now)
			for _, row := range mailboxResolverRows {
				input := normalizeSprayMailbox(row.input)
				want := sprayMailbox{name: input}
				if !row.hosted {
					want.exist = row.want
				}
				if got := r.Resolve(input); got != want {
					t.Errorf("Resolve(%q) = %+v, want %+v", input, got, want)
				}
			}
		})
	}
}

// A host taking logins has accounts and domains. An inventory without them is
// a read gone wrong, not proof that every name is missing.
func TestMailboxResolverEmptySnapshotIsUnknown(t *testing.T) {
	for name, empty := range map[string]checks.HostingSnapshot{
		"accounts, no domains": {Accounts: []string{"exampleco"}, Domains: map[string]string{}},
		"nil domains":          {Accounts: []string{"exampleco"}},
		"no accounts":          {Accounts: []string{}, Domains: map[string]string{"example.com": "exampleco"}},
		"nothing":              {Accounts: []string{}, Domains: map[string]string{}},
	} {
		t.Run(name, func(t *testing.T) {
			src := newFakeMailboxSource()
			populated := src.snapshot
			src.snapshot = empty
			clock := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
			r := newCPanelMailboxResolver(src, func() time.Time { return clock })
			names := []string{"a@example.org", "admin"}
			for _, row := range mailboxResolverRows {
				names = append(names, normalizeSprayMailbox(row.input))
			}
			for _, input := range names {
				if got, want := r.Resolve(input), (sprayMailbox{name: input}); got != want {
					t.Errorf("Resolve(%q) = %+v, want %+v", input, got, want)
				}
			}
			if src.inventoryCalls != 1 || len(src.mailboxCalls) != 0 {
				t.Errorf("%d Inventory and %d Mailboxes calls, want 1 and 0", src.inventoryCalls, len(src.mailboxCalls))
			}

			// Cached like a failed refresh: a good read waits for the TTL.
			src.snapshot = populated
			clock = clock.Add(mailboxResolverTTL)
			if got := r.Resolve("info@example.com"); got.exist != mailboxExistenceUnknown {
				t.Errorf("inside the TTL exist = %v, want Unknown", got.exist)
			}
			clock = clock.Add(time.Second)
			if got := r.Resolve("info@example.com"); got.exist != mailboxExists {
				t.Errorf("after the TTL exist = %v, want Exists", got.exist)
			}
		})
	}
}

func TestMailboxResolverNeverReadsTypedNames(t *testing.T) {
	src := newFakeMailboxSource()
	r := newCPanelMailboxResolver(src, time.Now)
	for _, name := range []string{
		"../x@example.com",
		"a/b",
		"x@../../etc",
		"x@example.com\x00",
		strings.Repeat("a", maxSprayMailboxBytes),
		strings.Repeat("a", maxSprayMailboxBytes-len("@example.com")) + "@example.com",
		"x@" + strings.Repeat("a", maxSprayMailboxBytes-len("x@.com")) + ".com",
	} {
		if got := r.Resolve(name); got.exist == mailboxExists {
			t.Errorf("Resolve(%q) = %+v, want Unknown or Missing", name, got)
		}
	}
	if len(src.mailboxCalls) != 0 {
		t.Errorf("a typed name reached the reader: %q", src.mailboxCalls)
	}
	// Control: the recorder does see a lookup that may read.
	r.Resolve("info@example.com")
	if len(src.mailboxCalls) != 1 || src.mailboxCalls[0] != "exampleco" {
		t.Errorf("Mailboxes calls = %q, want only exampleco", src.mailboxCalls)
	}
}

func TestMailboxResolverCaches(t *testing.T) {
	src := newFakeMailboxSource()
	clock := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	r := newCPanelMailboxResolver(src, func() time.Time { return clock })
	check := func(step string, want mailboxExistence, inventoryCalls, mailboxCalls int) {
		t.Helper()
		if got := r.Resolve("info@example.com"); got.exist != want {
			t.Errorf("%s: exist = %v, want %v", step, got.exist, want)
		}
		if src.inventoryCalls != inventoryCalls || len(src.mailboxCalls) != mailboxCalls {
			t.Errorf("%s: %d Inventory and %d Mailboxes calls, want %d and %d",
				step, src.inventoryCalls, len(src.mailboxCalls), inventoryCalls, mailboxCalls)
		}
	}
	check("first lookup", mailboxExists, 1, 1)
	check("second lookup", mailboxExists, 1, 1)
	clock = clock.Add(mailboxResolverTTL)
	check("at the TTL", mailboxExists, 1, 1)
	clock = clock.Add(time.Second)
	check("after the TTL", mailboxExists, 2, 2)

	// A failed refresh drops the snapshot and is not retried inside the TTL.
	src.inventoryErr = errors.New("read failed")
	clock = clock.Add(mailboxResolverTTL + time.Second)
	check("failed refresh", mailboxExistenceUnknown, 3, 2)
	clock = clock.Add(time.Second)
	check("inside the TTL of the failure", mailboxExistenceUnknown, 3, 2)
	src.inventoryErr = nil
	check("source recovered inside the TTL", mailboxExistenceUnknown, 3, 2)
	clock = clock.Add(mailboxResolverTTL)
	check("failure aged out", mailboxExists, 4, 3)
}

// A login flood must not turn one unreadable home into a read per failure.
func TestMailboxResolverCachesFailedLists(t *testing.T) {
	src := newFakeMailboxSource()
	src.mailboxesErr = errors.New("read failed")
	clock := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	r := newCPanelMailboxResolver(src, func() time.Time { return clock })
	for range 3 {
		if got := r.Resolve("info@example.com"); got.exist != mailboxExistenceUnknown {
			t.Fatalf("exist = %v, want Unknown", got.exist)
		}
	}
	if len(src.mailboxCalls) != 1 {
		t.Fatalf("%d Mailboxes calls inside the TTL, want 1", len(src.mailboxCalls))
	}
	src.mailboxesErr = nil
	clock = clock.Add(mailboxResolverTTL + time.Second)
	if got := r.Resolve("info@example.com"); got.exist != mailboxExists {
		t.Fatalf("after recovery exist = %v, want Exists", got.exist)
	}
}

func TestMailboxResolverAccountCacheBounded(t *testing.T) {
	src := &fakeMailboxSource{
		snapshot: checks.HostingSnapshot{Domains: map[string]string{}},
		lists:    map[string]map[string][]string{},
	}
	total := maxResolverAccounts + 10
	domain := func(i int) string { return fmt.Sprintf("d%05d.example.com", i) }
	for i := range total {
		owner := fmt.Sprintf("owner%05d", i)
		src.snapshot.Accounts = append(src.snapshot.Accounts, owner)
		src.snapshot.Domains[domain(i)] = owner
		src.lists[owner] = map[string][]string{domain(i): {"info"}}
	}
	clock := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	r := newCPanelMailboxResolver(src, func() time.Time {
		clock = clock.Add(time.Millisecond)
		return clock
	})
	for i := range total {
		if got := r.Resolve("info@" + domain(i)); got.exist != mailboxExists {
			t.Fatalf("%s: exist = %v, want Exists", domain(i), got.exist)
		}
		if len(r.accounts) > maxResolverAccounts {
			t.Fatalf("after %d owners the cache holds %d entries", i+1, len(r.accounts))
		}
	}
	if len(r.accounts) != maxResolverAccounts {
		t.Fatalf("cache holds %d entries, want %d", len(r.accounts), maxResolverAccounts)
	}
	calls := len(src.mailboxCalls)
	r.Resolve("info@" + domain(10))
	if len(src.mailboxCalls) != calls {
		t.Error("the oldest kept entry was read again")
	}
	r.Resolve("info@" + domain(0))
	if len(src.mailboxCalls) != calls+1 {
		t.Error("the oldest entry was not evicted")
	}
}

// The live source has no lock of its own and a burst of failures must not
// become a burst of reads. Both rest on the resolver's mutex.
func TestMailboxResolverSerialisesReads(t *testing.T) {
	src := newFakeMailboxSource()
	r := newCPanelMailboxResolver(src, time.Now)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if got := r.Resolve("info@example.com"); got.exist != mailboxExists {
				t.Errorf("exist = %v, want Exists", got.exist)
			}
		})
	}
	wg.Wait()
	if src.inventoryCalls != 1 || len(src.mailboxCalls) != 1 {
		t.Errorf("%d Inventory and %d Mailboxes calls, want 1 and 1", src.inventoryCalls, len(src.mailboxCalls))
	}
}
