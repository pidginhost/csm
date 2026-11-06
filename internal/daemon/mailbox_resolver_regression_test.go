package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMailboxResolverUnsupportedNamesStayUnknown(t *testing.T) {
	r := newCPanelMailboxResolver(newFakeMailboxSource(), time.Now)
	for _, name := range []string{
		"a/b", "a\\b", "..", "a b", "a\x00b", "\xff", strings.Repeat("a", 65),
		"info+folder@x.example.com", "info%folder@x.example.com",
		"info+folder@unhosted.example.com", "info%folder@unhosted.example.com",
		"__cpanel__service__auth__x@example.com",
		"__cpanel__service__auth__x@unhosted.example.com",
	} {
		if got, want := r.Resolve(name), (sprayMailbox{name: normalizeSprayMailbox(name)}); got != want {
			t.Errorf("Resolve(%q) = %+v, want %+v", name, got, want)
		}
	}
	// A normalized key at the length limit may have lost part of its domain.
	name := "info@" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 45) + ".example.com"
	if len(name) != maxSprayMailboxBytes {
		t.Fatal("fixture does not reach the key limit")
	}
	if got := r.Resolve(name); got.exist != mailboxExistenceUnknown {
		t.Errorf("possibly shortened key returned %+v, want Unknown", got)
	}
}

func TestMailboxResolverKeepsTruncationEvidence(t *testing.T) {
	r := newCPanelMailboxResolver(newFakeMailboxSource(), time.Now)
	// Cutting a long name after whitespace can yield a short, valid key. The
	// resolver needs the original input to distinguish it from a missing name.
	input := "nosuch@example.com" + strings.Repeat(" ", maxSprayMailboxBytes) + "suffix"
	want := sprayMailbox{name: "nosuch@example.com"}
	if normalizeSprayMailbox(input) != want.name {
		t.Fatal("fixture does not shorten to the expected key")
	}
	if got := r.Resolve(input); got != want {
		t.Errorf("shortened input = %+v, want %+v", got, want)
	}
	want.exist = mailboxMissing
	if got := r.Resolve(want.name); got != want {
		t.Errorf("complete input = %+v, want %+v", got, want)
	}
}

func TestMailboxResolverTypoCannotReturnOversizedKey(t *testing.T) {
	src := newFakeMailboxSource()
	domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 50) + ".example.com"
	src.snapshot.Domains[domain] = "exampleco"
	name := strings.Repeat("x", 62) + "@" + domain
	if len(name) != maxSprayMailboxBytes-1 {
		t.Fatal("fixture does not exercise a short key near an oversized mailbox")
	}
	for _, size := range []int{63, 64} {
		local := strings.Repeat("x", size)
		src.lists["exampleco"][domain] = []string{local}
		want := sprayMailbox{name: name}
		if size == 63 {
			want = sprayMailbox{name: local + "@" + domain, exist: mailboxExists}
		}
		if got := newCPanelMailboxResolver(src, time.Now).Resolve(name); got != want {
			t.Errorf("local length %d: Resolve = %+v, want %+v", size, got, want)
		}
	}
}

func TestMailboxResolverListsFollowInventory(t *testing.T) {
	for _, change := range []string{"added domain", "transferred domain", "recreated account", "failed refresh"} {
		t.Run(change, func(t *testing.T) {
			src := newFakeMailboxSource()
			if change == "transferred domain" {
				src.snapshot.Accounts = append(src.snapshot.Accounts, "previous")
				src.snapshot.Domains["new.example.com"] = "previous"
			}
			clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			r := newCPanelMailboxResolver(src, func() time.Time { return clock })
			r.Resolve("exampleco") // Refresh the inventory before filling the cache.
			clock = clock.Add(mailboxResolverTTL / 2)
			if got := r.Resolve("info@example.com"); got.exist != mailboxExists {
				t.Fatalf("initial lookup = %+v", got)
			}

			next := newFakeMailboxSource()
			domain := "example.com"
			switch change {
			case "added domain", "transferred domain":
				domain = "new.example.com"
				next.snapshot.Domains[domain] = "exampleco"
			case "recreated account":
				next.snapshot.Incarnations = map[string]string{"exampleco": "new"}
			case "failed refresh":
				src.inventoryErr = errors.New("inventory unavailable")
			}
			next.lists["exampleco"] = map[string][]string{domain: {"customer"}}
			src.snapshot, src.lists = next.snapshot, next.lists
			clock = clock.Add(mailboxResolverTTL/2 + time.Second)
			want := sprayMailbox{name: "customer@" + domain, exist: mailboxExists}
			if change == "failed refresh" {
				want.exist = mailboxExistenceUnknown
			}
			if got := r.Resolve(want.name); got != want {
				t.Errorf("after refresh = %+v, want %+v", got, want)
			}
		})
	}
}

func TestMailboxResolverFullCacheDoesNotRepeatReads(t *testing.T) {
	src := manyDomainSource(maxResolverAccounts + 1)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := newCPanelMailboxResolver(src, func() time.Time { return clock })
	for i := range maxResolverAccounts {
		if got := r.Resolve("info@" + hostedDomain(i)); got.exist != mailboxExists {
			t.Fatalf("warm lookup %d = %+v", i, got)
		}
	}
	for range 2 {
		if got := r.Resolve("info@" + hostedDomain(maxResolverAccounts)); got.exist != mailboxExistenceUnknown {
			t.Errorf("full cache lookup = %+v, want Unknown", got)
		}
		for i := range maxResolverAccounts {
			if got := r.Resolve("info@" + hostedDomain(i)); got.exist != mailboxExists {
				t.Fatalf("cached lookup %d = %+v", i, got)
			}
		}
	}
	if got := len(src.mailboxCalls); got != maxResolverAccounts {
		t.Errorf("%d reads within one snapshot, want %d", got, maxResolverAccounts)
	}
	clock = clock.Add(mailboxResolverTTL + time.Second)
	if got := r.Resolve("info@" + hostedDomain(maxResolverAccounts)); got.exist != mailboxExists {
		t.Errorf("after expiry = %+v, want Exists", got)
	}
}
