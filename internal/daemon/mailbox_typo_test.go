package daemon

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

func TestEditsWithin(t *testing.T) {
	for _, row := range []struct {
		a, b string
		k    int
		want int
		ok   bool
	}{
		{"info", "info", 2, 0, true},
		{"inof", "info", 2, 1, true},
		{"inf", "info", 2, 1, true},
		{"infoxx", "info", 2, 2, true},
		{"infoxxx", "info", 2, 0, false},
		{"sales", "info", 2, 0, false},
		{"", "ab", 2, 2, true},
		{"", "abc", 2, 0, false},
		{"", "", 0, 0, true},
		{"abc", "abc", 0, 0, true},
		{"abc", "abd", 0, 0, false},
		{"ab", "ba", 1, 1, true},
		// A swap is not edited again: this pair is 2 under Damerau-Levenshtein.
		{"ca", "abc", 2, 0, false},
		{"ca", "abc", 3, 3, true},
	} {
		got, ok := editsWithin(row.a, row.b, row.k)
		if ok != row.ok || (ok && got != row.want) {
			t.Errorf("editsWithin(%q, %q, %d) = %d, %v, want %d, %v", row.a, row.b, row.k, got, ok, row.want, row.ok)
		}
	}
}

// fullOSA is the textbook table, the reference for the budgeted walk.
func fullOSA(a, b string) int {
	d := make([][]int, len(a)+1)
	for i := range d {
		d[i] = make([]int, len(b)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			substitute := 1
			if a[i-1] == b[j-1] {
				substitute = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+substitute)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(a)][len(b)]
}

func TestEditsWithinMatchesFullTable(t *testing.T) {
	words := []string{""}
	for next := 0; len(words[next]) < 5; next++ {
		for _, c := range "abc" {
			words = append(words, words[next]+string(c))
		}
	}
	for _, a := range words {
		for _, b := range words {
			want := fullOSA(a, b)
			for k := range maxTypoEdits + 2 {
				got, ok := editsWithin(a, b, k)
				if ok != (want <= k) || (ok && got != want) {
					t.Fatalf("editsWithin(%q, %q, %d) = %d, %v, distance is %d", a, b, k, got, ok, want)
				}
			}
		}
	}
}

// newTypoMailboxSource hosts a second owner, so a domain typo has a choice.
func newTypoMailboxSource() *fakeMailboxSource {
	src := newFakeMailboxSource()
	src.snapshot.Accounts = append(src.snapshot.Accounts, "otherco")
	src.snapshot.Domains["example.org"] = "otherco"
	src.lists["otherco"] = map[string][]string{"example.org": {"info"}}
	return src
}

func TestMailboxResolverTypo(t *testing.T) {
	for _, row := range []struct {
		input string
		want  sprayMailbox
	}{
		{"inof@example.com", sprayMailbox{"info@example.com", mailboxExists}},
		{"infoo@example.com", sprayMailbox{"info@example.com", mailboxExists}},
		{"inof@example.com.", sprayMailbox{"info@example.com", mailboxExists}},
		{"zzzzz@example.com", sprayMailbox{"zzzzz@example.com", mailboxMissing}},
		{"infoxxx@example.com", sprayMailbox{"infoxxx@example.com", mailboxMissing}},
		{"info@exmaple.com", sprayMailbox{"info@example.com", mailboxExists}},
		{"inf@exampel.com", sprayMailbox{"info@example.com", mailboxExists}},
		{"inff@exampel.co", sprayMailbox{"inff@exampel.co", mailboxMissing}},
		{"info@example.cm", sprayMailbox{"info@example.com", mailboxExists}},
		{"info@example.cm.", sprayMailbox{"info@example.com", mailboxExists}},
		{"info@example.comxx", sprayMailbox{"info@example.com", mailboxExists}},
		{"zzzzz@exmaple.com", sprayMailbox{"zzzzz@exmaple.com", mailboxMissing}},
		{"zzzzz@exmaple.com.", sprayMailbox{"zzzzz@exmaple.com.", mailboxMissing}},

		// The owner name is a mailbox, so it can be mistyped like one.
		{"exampelco@example.com", sprayMailbox{"exampleco@example.com", mailboxExists}},
		{"exampleco@exmaple.com", sprayMailbox{"exampleco@example.com", mailboxExists}},
		{"exampelco@exmaple.com", sprayMailbox{"exampleco@example.com", mailboxExists}},
		{"otherco@example.or", sprayMailbox{"otherco@example.org", mailboxExists}},
		{"exampelco@example.or", sprayMailbox{"exampelco@example.or", mailboxMissing}},

		// A near domain with no account to read cannot prove a name missing.
		{"nosuch@example.nt", sprayMailbox{"nosuch@example.nt", mailboxExistenceUnknown}},
		{"nosuch@example.nt.", sprayMailbox{"nosuch@example.nt.", mailboxExistenceUnknown}},
		{"info@example.nt", sprayMailbox{"info@example.nt", mailboxExistenceUnknown}},

		// On a hosted domain an extension is decided before any typo step.
		{"in+f@example.com", sprayMailbox{"in+f@example.com", mailboxExistenceUnknown}},
		{"in%f@example.com", sprayMailbox{"in%f@example.com", mailboxExistenceUnknown}},
		// On a mistyped domain it only ever matches by edits.
		{"in+fo@exmaple.com", sprayMailbox{"info@example.com", mailboxExists}},
		{"in+foo@exmaple.com", sprayMailbox{"in+foo@exmaple.com", mailboxMissing}},
	} {
		r := newCPanelMailboxResolver(newTypoMailboxSource(), time.Now)
		if got := r.Resolve(row.input); got != row.want {
			t.Errorf("Resolve(%q) = %+v, want %+v", row.input, got, row.want)
		}
	}
}

func TestMailboxResolverTypoOrder(t *testing.T) {
	src := &fakeMailboxSource{
		snapshot: checks.HostingSnapshot{
			Accounts: []string{"bob", "owner1", "owner2", "owner3", "owner4", "owner5", "owner6"},
			Domains: map[string]string{
				"a.example.com":   "bob",
				"b9.example.com":  "owner1",
				"b22.example.com": "owner2",
				"c1.example.org":  "owner3",
				"c22.example.org": "owner4",
				"d1.example.net":  "owner5",
				"d2.example.net":  "owner6",
			},
		},
		lists: map[string]map[string][]string{
			"bob":    {"a.example.com": {"abcd", "abce", "ann", "ann.a", "bot"}},
			"owner1": {"b9.example.com": {"sales"}},
			"owner2": {"b22.example.com": {"sales"}},
			"owner3": {"c1.example.org": {"salesx"}},
			"owner4": {"c22.example.org": {"sales"}},
			"owner5": {"d1.example.net": {"sales"}},
			"owner6": {"d2.example.net": {"sales"}},
		},
	}
	r := newCPanelMailboxResolver(src, time.Now)
	for _, row := range []struct{ why, input, want string }{
		{"fewer edits beat a smaller address", "zabce@a.example.com", "abce@a.example.com"},
		{"a tie goes to the smaller address, not the smaller local part", "anna@a.example.com", "ann.a@a.example.com"},
		{"the owner ties with listed names", "bop@a.example.com", "bob@a.example.com"},
		{"the total beats a smaller address", "sales@b.example.com", "sales@b9.example.com"},
		{"the total counts domain and local edits alike", "sales@c.example.org", "sales@c22.example.org"},
		{"equal domains tie on the address", "sales@d.example.net", "sales@d1.example.net"},
	} {
		want := sprayMailbox{row.want, mailboxExists}
		if got := r.Resolve(row.input); got != want {
			t.Errorf("%s: Resolve(%q) = %+v, want %+v", row.why, row.input, got, want)
		}
	}
}

func TestMailboxResolverTypoSkippedCandidate(t *testing.T) {
	failure := errors.New("read failed")
	for name, breakLists := range map[string]func(*fakeMailboxSource){
		"mailboxes error":  func(f *fakeMailboxSource) { f.mailboxesErr = failure },
		"incomplete lists": func(f *fakeMailboxSource) { f.incomplete = true },
	} {
		t.Run(name, func(t *testing.T) {
			src := newTypoMailboxSource()
			breakLists(src)
			r := newCPanelMailboxResolver(src, time.Now)
			want := sprayMailbox{"info@exmaple.com", mailboxExistenceUnknown}
			if got := r.Resolve(want.name); got != want {
				t.Errorf("Resolve(%q) = %+v, want %+v", want.name, got, want)
			}
		})
	}

	src := &fakeMailboxSource{
		snapshot: checks.HostingSnapshot{
			Accounts:   []string{"broken", "working"},
			Domains:    map[string]string{"a1.example.com": "broken", "a2.example.com": "working"},
			Unresolved: map[string]bool{"a3.example.com": true},
		},
		lists:      map[string]map[string][]string{"working": {"a2.example.com": {"info"}}},
		unreadable: map[string]bool{"broken": true},
	}
	r := newCPanelMailboxResolver(src, time.Now)
	for range 2 {
		unknown := sprayMailbox{"nosuch@a.example.com", mailboxExistenceUnknown}
		if got := r.Resolve(unknown.name); got != unknown {
			t.Errorf("no match with skipped candidates: got %+v, want %+v", got, unknown)
		}
		match := sprayMailbox{"info@a2.example.com", mailboxExists}
		if got := r.Resolve("info@a.example.com"); got != match {
			t.Errorf("a match beats skipped candidates: got %+v, want %+v", got, match)
		}
	}
	if got := len(src.mailboxCalls); got != 2 {
		t.Errorf("%d Mailboxes calls, want 2: a failed read is cached like a good one: %q", got, src.mailboxCalls)
	}
}

func TestMailboxTypoIndexFollowsSnapshot(t *testing.T) {
	src := newFakeMailboxSource()
	clock := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	r := newCPanelMailboxResolver(src, func() time.Time { return clock })
	check := func(step string, want mailboxExistence) {
		t.Helper()
		if got := r.Resolve("info@exmaple.org"); got.exist != want {
			t.Errorf("%s: exist = %v, want %v", step, got.exist, want)
		}
	}
	check("not hosted yet", mailboxMissing)

	added := newTypoMailboxSource()
	src.snapshot, src.lists = added.snapshot, added.lists
	check("inside the TTL", mailboxMissing)
	clock = clock.Add(mailboxResolverTTL + time.Second)
	check("after the refresh", mailboxExists)

	src.snapshot = newFakeMailboxSource().snapshot
	clock = clock.Add(mailboxResolverTTL + time.Second)
	check("domain removed", mailboxMissing)
}

func hostedDomain(i int) string { return fmt.Sprintf("d%05d.example.com", i) }

// manyDomainSource hosts count domains of one byte length, each with its own
// owner, so a typed domain of that length scans all of them.
func manyDomainSource(count int) *fakeMailboxSource {
	src := &fakeMailboxSource{
		snapshot: checks.HostingSnapshot{Domains: map[string]string{}},
		lists:    map[string]map[string][]string{},
	}
	for i := range count {
		owner := fmt.Sprintf("owner%05d", i)
		src.snapshot.Accounts = append(src.snapshot.Accounts, owner)
		src.snapshot.Domains[hostedDomain(i)] = owner
		src.lists[owner] = map[string][]string{hostedDomain(i): {"info"}}
	}
	return src
}

func TestMailboxTypoIndexDoesNotGrow(t *testing.T) {
	const domains, lookups, nearEvery = 2000, 10000, 100
	src := manyDomainSource(domains)
	clock := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	r := newCPanelMailboxResolver(src, func() time.Time { return clock })
	r.Resolve("seed@example.org")
	before := mailboxTypoIndex{}
	indexed := 0
	for size, bucket := range r.typoIndex {
		before[size] = slices.Clone(bucket)
		indexed += len(bucket)
	}
	if indexed != domains {
		t.Fatalf("index holds %d domains, want %d", indexed, domains)
	}

	matched := map[string]bool{}
	for i := range lookups {
		name := fmt.Sprintf("nosuch%05d@u%05d.example.org", i, i)
		if i%nearEvery == 0 {
			near := fmt.Sprintf("d%05d.example.cm", i/nearEvery)
			name = fmt.Sprintf("nosuch%05d@%s", i, near)
			for j := range domains {
				if _, ok := editsWithin(near, hostedDomain(j), maxTypoEdits); ok {
					matched[src.snapshot.Domains[hostedDomain(j)]] = true
				}
			}
		}
		if got, want := r.Resolve(name), (sprayMailbox{name, mailboxMissing}); got != want {
			t.Fatalf("Resolve(%q) = %+v, want %+v", name, got, want)
		}
	}

	if !reflect.DeepEqual(before, r.typoIndex) {
		t.Error("a lookup changed the index")
	}
	if src.inventoryCalls != 1 {
		t.Errorf("%d Inventory calls, want 1", src.inventoryCalls)
	}
	if len(matched) == 0 {
		t.Fatal("no lookup had a candidate, the cache bound below proves nothing")
	}
	if len(r.accounts) != len(matched) || len(src.mailboxCalls) != len(matched) {
		t.Errorf("%d cached accounts and %d reads, want %d each", len(r.accounts), len(src.mailboxCalls), len(matched))
	}
	for account := range r.accounts {
		if !matched[account] {
			t.Errorf("read %s, the owner of no candidate", account)
		}
	}
}

func BenchmarkMailboxResolverUnhostedTypo(b *testing.B) {
	r := newCPanelMailboxResolver(manyDomainSource(20000), time.Now)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		i++
		name := fmt.Sprintf("nosuch%d@u%05d.example.org", i, i)
		if got := r.Resolve(name); got.exist != mailboxMissing {
			b.Fatalf("Resolve(%q) = %+v, want Missing", name, got)
		}
	}
}
