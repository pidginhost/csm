package daemon

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/antispam/dovecot"
	"github.com/pidginhost/csm/internal/antispam/learnwatch"
	"github.com/pidginhost/csm/internal/checks"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/platform"
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

// Platform detection must follow startup's config overrides, so construction
// takes the already detected host instead of probing in New.
func newMailboxResolver(host platform.Info) mailboxResolver {
	if !host.IsCPanel() {
		return nil
	}
	return newCPanelMailboxResolver(newLiveMailboxSource(learnwatch.DefaultSource), time.Now)
}

// resolveSprayMailbox gives the mailbox a failed login on name counts against.
// A verdict from the log is about this login while the resolver can be a TTL
// behind, so the resolver cannot overturn it, except that a Missing name near
// a real mailbox is a typo of that mailbox.
func resolveSprayMailbox(r mailboxResolver, name string, verdict mailboxExistence) sprayMailbox {
	key := normalizeSprayMailbox(name)
	if r == nil || verdict == mailboxExists {
		return sprayMailbox{name: key, exist: verdict}
	}
	mb := r.Resolve(name)
	if verdict == mailboxExistenceUnknown || (mb.exist == mailboxExists && mb.name != key) {
		return mb
	}
	return sprayMailbox{name: key, exist: mailboxMissing}
}

// sprayMailboxFor is resolveSprayMailbox with the daemon's resolver. Callers
// hold no tracker lock. The lookup runs only while the spray rules are on.
func (d *Daemon) sprayMailboxFor(name string, verdict mailboxExistence) sprayMailbox {
	if !d.sprayRulesOn() {
		return resolveSprayMailbox(nil, name, verdict)
	}
	return resolveSprayMailbox(d.mailboxes, name, verdict)
}

// sprayRulesOn reports whether anything reads mailbox existence.
func (d *Daemon) sprayRulesOn() bool {
	return d.mailSpray != nil && d.mailSpray.Mode() != sprayOff
}

// cpanelMailboxSource reads cPanel's accounts, domains and mailboxes.
type cpanelMailboxSource interface {
	Inventory() (checks.HostingSnapshot, error)
	// Mailboxes returns the local parts of each domain the last Inventory
	// lists for account, sorted, distinct and in the spelling of
	// normalizeSprayMailbox, as are the domain keys. complete is false when
	// the read skipped anything.
	Mailboxes(account string) (lists map[string][]string, complete bool, err error)
}

// accountMailboxes belongs to one inventory snapshot. Failed and partial reads
// are kept too, so each account costs at most one read before the next snapshot.
type accountMailboxes struct {
	lists  map[string][]string
	usable bool
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
	typoIndex      mailboxTypoIndex
	accounts       map[string]accountMailboxes
}

func newCPanelMailboxResolver(src cpanelMailboxSource, now func() time.Time) *cpanelMailboxResolver {
	return &cpanelMailboxResolver{src: src, now: now, accounts: map[string]accountMailboxes{}}
}

// Resolve takes the original login name: normalizing before lookup would lose
// evidence of truncation. An answer it cannot give is Unknown. It returns the
// normalized key, except that a typo match takes the real mailbox's spelling,
// so one mailbox is one key.
func (r *cpanelMailboxResolver) Resolve(input string) sprayMailbox {
	name := normalizeSprayMailbox(input)
	if name == "" {
		return sprayMailbox{}
	}
	// A cut after whitespace can leave a valid key shorter than the limit.
	if len(strings.TrimSpace(input)) >= maxSprayMailboxBytes || strings.HasPrefix(name, "__cpanel__") {
		return sprayMailbox{name: name, exist: mailboxExistenceUnknown}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refreshSnapshot(r.now())
	if !r.snapshotUsable {
		return sprayMailbox{name: name, exist: mailboxExistenceUnknown}
	}
	at := strings.LastIndexByte(name, '@')
	if at < 0 {
		return sprayMailbox{name: name, exist: r.accountNameExistence(name)}
	}
	local, domain := name[:at], name[at+1:]
	if !dovecot.ValidMailbox(local) || !dovecot.ValidDomain(domain) || r.snapshot.Unresolved[domain] {
		return sprayMailbox{name: name, exist: mailboxExistenceUnknown}
	}
	if owner, hosted := r.snapshot.Domains[domain]; hosted {
		lists, usable := r.accountLists(owner)
		if !usable {
			return sprayMailbox{name: name, exist: mailboxExistenceUnknown}
		}
		if _, listed := slices.BinarySearch(lists[domain], local); listed || local == owner {
			return sprayMailbox{name: name, exist: mailboxExists}
		}
		if hasAddressExtension(local) {
			return sprayMailbox{name: name, exist: mailboxExistenceUnknown}
		}
	}
	return r.resolveTypo(name, local, domain)
}

// accountNameExistence answers for a login with no domain.
func (r *cpanelMailboxResolver) accountNameExistence(name string) mailboxExistence {
	if !admission.ValidAccountName(name) {
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
	// Before its first read the lookup counts as up, so a first failure is news
	// and a first good read is not.
	wasDown := !r.snapshotAt.IsZero() && !r.snapshotUsable
	r.snapshotAt = now
	snapshot, err := r.src.Inventory()
	// A host taking logins has accounts and domains. A read without them says
	// nothing about the names asked, and outage traffic is never evidence.
	r.snapshot = snapshot
	r.snapshotUsable = err == nil && len(snapshot.Accounts) > 0 && len(snapshot.Domains) > 0
	r.typoIndex = newMailboxTypoIndex(snapshot)
	// Lists were read for the previous ownership and account identities. Even
	// a younger list cannot answer for domains introduced by this snapshot.
	clear(r.accounts)
	switch {
	case wasDown && r.snapshotUsable:
		csmlog.Info("mailbox lookup available again")
	case !wasDown && !r.snapshotUsable:
		if err == nil {
			err = errors.New("no accounts or domains listed")
		}
		csmlog.Warn("mailbox lookup unavailable, failed logins stay unknown", "err", err)
	}
}

func (r *cpanelMailboxResolver) accountLists(account string) (map[string][]string, bool) {
	if cached, ok := r.accounts[account]; ok {
		return cached.lists, cached.usable
	}
	// Evicting live entries lets rotating login names force repeated reads.
	// Capacity is available again when the inventory expires.
	if len(r.accounts) >= maxResolverAccounts {
		return nil, false
	}
	entry := accountMailboxes{}
	if lists, complete, err := r.src.Mailboxes(account); err == nil && complete {
		entry.lists, entry.usable = lists, true
	}
	r.accounts[account] = entry
	return entry.lists, entry.usable
}
