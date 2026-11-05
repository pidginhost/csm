package daemon

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/store"
)

// knownCustomerTTL is how long one successful login keeps an address known.
const knownCustomerTTL = 30 * 24 * time.Hour

// maxKnownCustomers bounds the set. A full set drops its oldest logins in one
// batch, down to 95%, so each new address does not pay for a scan.
const maxKnownCustomers = 50000

// maxKnownCustomerIPsPerAccount bounds the addresses one account may hold, so
// one stolen credential cannot push every other customer out of the set.
const maxKnownCustomerIPsPerAccount = 64

// Kinds of successful customer login.
const (
	knownCustomerCpanel  = "cpanel"
	knownCustomerWebmail = "webmail"
	knownCustomerSMTP    = "smtp"
	knownCustomerIMAP    = "imap"
	knownCustomerFTP     = "ftp"
)

// knownCustomers remembers addresses that logged in successfully as a
// customer, with the last such login. Only real successes are noted, so an
// attacker who can only fail logins never enters the set. Its mutex is a
// leaf: the infra lookup and store I/O run outside it.
type knownCustomers struct {
	now func() time.Time
	// isInfra reports addresses that are never stored. Set once before log
	// readers start.
	isInfra func(ip string) bool

	mu       sync.Mutex
	entries  map[netip.Addr]store.KnownCustomer
	accounts map[string]map[netip.Addr]struct{} // addresses whose last login named the account
	dirty    map[netip.Addr]struct{}            // to write at the next save
	deleted  map[string]struct{}                // stored keys to remove at the next save
}

func newKnownCustomers(now func() time.Time) *knownCustomers {
	return &knownCustomers{
		now:      now,
		entries:  make(map[netip.Addr]store.KnownCustomer),
		accounts: make(map[string]map[netip.Addr]struct{}),
		dirty:    make(map[netip.Addr]struct{}),
		deleted:  make(map[string]struct{}),
	}
}

func knownCustomerExpired(at, now time.Time) bool {
	return now.Sub(at) >= knownCustomerTTL
}

// customerAddr is the canonical address ip is stored under, or false when it
// can never be a customer entry.
func (k *knownCustomers) customerAddr(ip string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || (k.isInfra != nil && k.isInfra(addr.String())) {
		return netip.Addr{}, false
	}
	return addr, true
}

// Note records a successful login of kind from ip at at. A login older than
// the TTL is ignored and one stamped in the future counts as now.
func (k *knownCustomers) Note(ip, kind, account string, at time.Time) {
	if k == nil {
		return
	}
	addr, ok := k.customerAddr(ip)
	if !ok {
		return
	}
	now := k.now()
	if at.After(now) {
		at = now
	}
	if knownCustomerExpired(at, now) {
		return
	}
	c := store.KnownCustomer{Kind: kind, Account: normalizeSprayMailbox(account), At: at}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.putLocked(addr, c)
}

// putLocked stores c for addr unless addr already holds a newer login.
func (k *knownCustomers) putLocked(addr netip.Addr, c store.KnownCustomer) {
	old, exists := k.entries[addr]
	if exists && old.At.After(c.At) {
		return
	}
	if !exists && len(k.entries) >= maxKnownCustomers {
		k.evictOldestLocked()
	}
	if exists && old.Account != c.Account {
		k.unindexLocked(addr, old.Account)
	}
	k.entries[addr] = c
	k.dirty[addr] = struct{}{}
	delete(k.deleted, addr.String())
	if c.Account == "" {
		return
	}
	held := k.accounts[c.Account]
	if held == nil {
		held = make(map[netip.Addr]struct{})
		k.accounts[c.Account] = held
	}
	held[addr] = struct{}{}
	if len(held) <= maxKnownCustomerIPsPerAccount {
		return
	}
	// The account's oldest address goes, which may be the one just noted.
	var oldest customerEntry
	for a := range held {
		if e := (customerEntry{a, k.entries[a]}); !oldest.addr.IsValid() || compareCustomerEntries(e, oldest) < 0 {
			oldest = e
		}
	}
	k.removeLocked(oldest.addr)
}

// customerEntry is one address with its last login.
type customerEntry struct {
	addr netip.Addr
	c    store.KnownCustomer
}

// compareCustomerEntries orders the oldest login first.
func compareCustomerEntries(a, b customerEntry) int {
	if c := a.c.At.Compare(b.c.At); c != 0 {
		return c
	}
	return a.addr.Compare(b.addr)
}

// evictOldestLocked drops the oldest entries until the set is at 95% of its
// cap.
func (k *knownCustomers) evictOldestLocked() {
	all := make([]customerEntry, 0, len(k.entries))
	for a, c := range k.entries {
		all = append(all, customerEntry{a, c})
	}
	slices.SortFunc(all, compareCustomerEntries)
	for _, e := range all[:len(all)-maxKnownCustomers*95/100] {
		k.removeLocked(e.addr)
	}
}

func (k *knownCustomers) unindexLocked(addr netip.Addr, account string) {
	held := k.accounts[account]
	delete(held, addr)
	if len(held) == 0 {
		delete(k.accounts, account)
	}
}

func (k *knownCustomers) removeLocked(addr netip.Addr) {
	c, ok := k.entries[addr]
	if !ok {
		return
	}
	delete(k.entries, addr)
	if c.Account != "" {
		k.unindexLocked(addr, c.Account)
	}
	delete(k.dirty, addr)
	k.deleted[addr.String()] = struct{}{}
}

func customerHit(addr netip.Addr, c store.KnownCustomer) blockdigest.CustomerHit {
	return blockdigest.CustomerHit{IP: addr.String(), Kind: c.Kind, Account: c.Account, At: c.At}
}

// Lookup returns the last customer login from ip within the TTL.
func (k *knownCustomers) Lookup(ip string) (blockdigest.CustomerHit, bool) {
	if k == nil {
		return blockdigest.CustomerHit{}, false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return blockdigest.CustomerHit{}, false
	}
	addr = addr.Unmap()
	now := k.now()
	k.mu.Lock()
	c, ok := k.entries[addr]
	k.mu.Unlock()
	if !ok || knownCustomerExpired(c.At, now) {
		return blockdigest.CustomerHit{}, false
	}
	return customerHit(addr, c), true
}

// Within counts the known customers inside p and returns up to limit of
// them, the most recent first.
func (k *knownCustomers) Within(p netip.Prefix, limit int) (n int, sample []blockdigest.CustomerHit) {
	if k == nil || !p.IsValid() {
		return 0, nil
	}
	p = p.Masked()
	now := k.now()
	var matches []customerEntry
	k.mu.Lock()
	// A linear scan of at most maxKnownCustomers entries per call; index by
	// network if subnet blocks ever become frequent.
	for addr, c := range k.entries {
		if !p.Contains(addr) || knownCustomerExpired(c.At, now) {
			continue
		}
		n++
		if limit > 0 {
			matches = append(matches, customerEntry{addr, c})
		}
	}
	k.mu.Unlock()
	slices.SortFunc(matches, func(a, b customerEntry) int { return compareCustomerEntries(b, a) })
	for _, m := range matches[:min(limit, len(matches))] {
		sample = append(sample, customerHit(m.addr, m.c))
	}
	return n, sample
}

// Purge drops entries past the TTL.
func (k *knownCustomers) Purge() {
	now := k.now()
	k.mu.Lock()
	defer k.mu.Unlock()
	for addr, c := range k.entries {
		if knownCustomerExpired(c.At, now) {
			k.removeLocked(addr)
		}
	}
}

// Load merges saved entries, keeping the newer login per address. Saved keys
// it cannot use (unparsable, not a customer address, past the TTL) or that
// are not canonical are queued for deletion, so the bucket sheds them.
func (k *knownCustomers) Load(saved map[string]store.KnownCustomer) {
	type entry struct {
		raw  string
		addr netip.Addr
		c    store.KnownCustomer
	}
	now := k.now()
	valid := make([]entry, 0, len(saved))
	var dropped []string
	for raw, c := range saved {
		addr, ok := k.customerAddr(raw)
		if !ok || knownCustomerExpired(c.At, now) {
			dropped = append(dropped, raw)
			continue
		}
		if c.At.After(now) {
			c.At = now
		}
		c.Account = normalizeSprayMailbox(c.Account)
		valid = append(valid, entry{raw, addr, c})
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, raw := range dropped {
		k.deleted[raw] = struct{}{}
	}
	for _, e := range valid {
		canonical := e.raw == e.addr.String()
		if !canonical {
			k.deleted[e.raw] = struct{}{}
		}
		k.putLocked(e.addr, e.c)
		// The store already holds an entry loaded unchanged.
		if cur, ok := k.entries[e.addr]; ok && canonical && sameKnownCustomer(cur, saved[e.raw]) {
			delete(k.dirty, e.addr)
		}
	}
}

func sameKnownCustomer(a, b store.KnownCustomer) bool {
	return a.Kind == b.Kind && a.Account == b.Account && a.At.Equal(b.At)
}

// Changes returns what changed since the last call: entries to write and
// stored keys to delete.
func (k *knownCustomers) Changes() (upserts map[string]store.KnownCustomer, deletes []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	upserts = make(map[string]store.KnownCustomer, len(k.dirty))
	for addr := range k.dirty {
		upserts[addr.String()] = k.entries[addr]
	}
	deletes = make([]string, 0, len(k.deleted))
	for raw := range k.deleted {
		deletes = append(deletes, raw)
	}
	slices.Sort(deletes)
	clear(k.dirty)
	clear(k.deleted)
	return upserts, deletes
}

// requeue marks the keys of a failed save for the next one: a key still held
// is written with its current value, any other is deleted. Pending deletes
// stay bounded; one dropped here leaves a stale record that the next load
// skips or caps and queues for deletion again.
func (k *knownCustomers) requeue(upserts map[string]store.KnownCustomer, deletes []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	mark := func(raw string) {
		if addr, err := netip.ParseAddr(raw); err == nil && addr.String() == raw {
			if _, ok := k.entries[addr]; ok {
				k.dirty[addr] = struct{}{}
				return
			}
		}
		if len(k.deleted) < maxKnownCustomers {
			k.deleted[raw] = struct{}{}
		}
	}
	for raw := range upserts {
		mark(raw)
	}
	for _, raw := range deletes {
		mark(raw)
	}
}

// noteFTPCustomers remembers the addresses of successful FTP logins.
func (d *Daemon) noteFTPCustomers(findings []alert.Finding) {
	for _, f := range findings {
		switch f.Check {
		case "ftp_login", "ftp_login_after_bruteforce":
			d.knownCustomers.Note(f.SourceIP, knownCustomerFTP, f.TenantID, f.Timestamp)
		}
	}
}

// loadKnownCustomers seeds the set from the last run.
func (d *Daemon) loadKnownCustomers() {
	sdb := store.Global()
	if sdb == nil {
		return
	}
	saved, err := sdb.LoadKnownCustomers()
	if err != nil {
		csmlog.Warn("known customer load failed", "err", err)
		return
	}
	d.knownCustomers.Load(saved)
}

// persistKnownCustomers purges expired entries and saves what changed.
func (d *Daemon) persistKnownCustomers() {
	d.knownCustomers.Purge()
	upserts, deletes := d.knownCustomers.Changes()
	sdb := store.Global()
	if sdb == nil || len(upserts)+len(deletes) == 0 {
		return
	}
	if err := sdb.SaveKnownCustomers(upserts, deletes); err != nil {
		d.knownCustomers.requeue(upserts, deletes)
		csmlog.Warn("known customer save failed", "err", err)
	}
}

// runKnownCustomers saves the set every minute and on stop.
func (d *Daemon) runKnownCustomers() {
	defer d.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-d.stopCh:
			d.persistKnownCustomers()
			return
		case <-t.C:
			d.persistKnownCustomers()
		}
	}
}
