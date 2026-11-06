package daemon

import (
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/antispam/dovecot"
	"github.com/pidginhost/csm/internal/checks"
)

const (
	// mailboxResolverTTL is how long a read of cPanel's state answers. A new
	// or deleted mailbox can get its old answer for this long.
	mailboxResolverTTL = 2 * time.Minute
	// maxResolverAccounts bounds the accounts whose mailbox lists are held.
	maxResolverAccounts = 4096
)

// mailboxResolver answers whether a failed login name is a real mailbox.
type mailboxResolver interface {
	Resolve(name string) sprayMailbox
}

// cpanelMailboxSource reads cPanel's accounts, domains and mailboxes.
type cpanelMailboxSource interface {
	Inventory() (checks.HostingSnapshot, error)
	// Mailboxes returns the local parts of each of account's domains, sorted,
	// distinct and in the spelling of normalizeSprayMailbox, as are the domain
	// keys. complete is false when the read skipped anything.
	Mailboxes(account string) (lists map[string][]string, complete bool, err error)
}

// accountMailboxes is one read of an account's lists. A failed or partial
// read is kept too: it holds no lists, and it costs one read per TTL however
// many logins ask.
type accountMailboxes struct {
	lists  map[string][]string
	usable bool
	at     time.Time
}

// cpanelMailboxResolver answers from cached cPanel state. A typed name is
// only compared with that state: the source is only ever asked for owners
// named in the snapshot.
type cpanelMailboxResolver struct {
	src cpanelMailboxSource
	now func() time.Time

	// mu is a leaf lock held across source reads, so a burst of logins costs
	// one read and the source needs no lock of its own.
	mu             sync.Mutex
	snapshot       checks.HostingSnapshot
	snapshotUsable bool
	snapshotAt     time.Time
	accounts       map[string]accountMailboxes
}

func newCPanelMailboxResolver(src cpanelMailboxSource, now func() time.Time) *cpanelMailboxResolver {
	return &cpanelMailboxResolver{src: src, now: now, accounts: map[string]accountMailboxes{}}
}

// Resolve answers for name, the output of normalizeSprayMailbox. An answer it
// cannot give is Unknown. The name comes back as given, except that a mailbox
// found by dropping the domain's trailing dot takes its real spelling, so one
// mailbox is one key.
func (r *cpanelMailboxResolver) Resolve(name string) sprayMailbox {
	if name == "" {
		return sprayMailbox{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.refreshSnapshot(now)
	if !r.snapshotUsable {
		return sprayMailbox{name: name, exist: mailboxExistenceUnknown}
	}
	at := strings.LastIndexByte(name, '@')
	if at < 0 {
		return sprayMailbox{name: name, exist: r.accountNameExistence(name)}
	}
	address := strings.TrimSuffix(name, ".")
	local, domain := address[:at], address[at+1:]
	if !dovecot.ValidMailbox(local) || !dovecot.ValidDomain(domain) || r.snapshot.Unresolved[domain] {
		return sprayMailbox{name: name, exist: mailboxExistenceUnknown}
	}
	owner, hosted := r.snapshot.Domains[domain]
	if !hosted {
		return sprayMailbox{name: name, exist: mailboxMissing}
	}
	lists, usable := r.accountLists(owner, now)
	if !usable {
		return sprayMailbox{name: name, exist: mailboxExistenceUnknown}
	}
	if _, listed := slices.BinarySearch(lists[domain], local); listed || local == owner {
		return sprayMailbox{name: address, exist: mailboxExists}
	}
	if hasAddressExtension(local) {
		return sprayMailbox{name: name, exist: mailboxExistenceUnknown}
	}
	return sprayMailbox{name: name, exist: mailboxMissing}
}

// accountNameExistence answers for a login with no domain.
func (r *cpanelMailboxResolver) accountNameExistence(name string) mailboxExistence {
	if strings.HasPrefix(name, "__cpanel__") || hasAddressExtension(name) {
		return mailboxExistenceUnknown
	}
	if _, found := slices.BinarySearch(r.snapshot.Accounts, name); found {
		return mailboxExists
	}
	return mailboxMissing
}

// hasAddressExtension reports a name that may be a mailbox spelled another
// way: + and % can start an extension or stand in for the @ of a login.
func hasAddressExtension(s string) bool {
	return strings.ContainsAny(s, "+%")
}

func (r *cpanelMailboxResolver) refreshSnapshot(now time.Time) {
	if !r.snapshotAt.IsZero() && now.Sub(r.snapshotAt) <= mailboxResolverTTL {
		return
	}
	r.snapshotAt = now
	snapshot, err := r.src.Inventory()
	// A host taking logins has accounts and domains. A read without them says
	// nothing about the names asked, and outage traffic is never evidence.
	r.snapshot = snapshot
	r.snapshotUsable = err == nil && len(snapshot.Accounts) > 0 && len(snapshot.Domains) > 0
}

func (r *cpanelMailboxResolver) accountLists(account string, now time.Time) (map[string][]string, bool) {
	cached, ok := r.accounts[account]
	if ok && now.Sub(cached.at) <= mailboxResolverTTL {
		return cached.lists, cached.usable
	}
	if !ok && len(r.accounts) >= maxResolverAccounts {
		r.evictOldestAccount()
	}
	entry := accountMailboxes{at: now}
	if lists, complete, err := r.src.Mailboxes(account); err == nil && complete {
		entry.lists, entry.usable = lists, true
	}
	r.accounts[account] = entry
	return entry.lists, entry.usable
}

// ponytail: linear scan of the capped map; a heap if lookups past the cap get hot.
func (r *cpanelMailboxResolver) evictOldestAccount() {
	var oldest string
	var oldestAt time.Time
	for account, entry := range r.accounts {
		if oldest == "" || entry.at.Before(oldestAt) {
			oldest, oldestAt = account, entry.at
		}
	}
	delete(r.accounts, oldest)
}
