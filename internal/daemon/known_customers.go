package daemon

import (
	"container/heap"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/blockdigest"
	"github.com/pidginhost/csm/internal/checks"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/store"
)

// knownCustomerTTL is how long one successful login keeps an address known.
const knownCustomerTTL = 30 * 24 * time.Hour

// maxKnownCustomers bounds the set, split in two fixed halves by login
// source. Any local user can write syslog with logger, so each half trims
// only itself: a flood read from one source never evicts the other. A full
// half trims in one batch, down to 95%, so each new address does not pay for
// a scan.
const maxKnownCustomers = 50000

// maxSyslogCustomers bounds the logins read from syslog.
const maxSyslogCustomers = maxKnownCustomers / 2

// maxServiceCustomers bounds the logins read from session_log and the Exim
// mainlog.
const maxServiceCustomers = maxKnownCustomers - maxSyslogCustomers

// maxKnownCustomerIPsPerAccount bounds the addresses one account holds from
// one login source; logins without an account name form one group. Rotating
// credentials or addresses cannot take over the set.
const maxKnownCustomerIPsPerAccount = 64

// Kinds of successful customer login.
const (
	knownCustomerCpanel  = "cpanel"
	knownCustomerWebmail = "webmail"
	knownCustomerSMTP    = "smtp"
	knownCustomerIMAP    = "imap"
	knownCustomerPOP     = "pop"
	knownCustomerFTP     = "ftp"
)

// loginSource is the log a login was read from.
type loginSource bool

const (
	serviceLog loginSource = false // written only by the service: session_log, the Exim mainlog
	syslogFed  loginSource = true  // syslog, which any local user can write with logger
)

// loginFromSyslog reports whether a login of kind was read from syslog.
// cPanel and webmail logins come only from session_log, FTP, IMAP and POP
// only from syslog; SMTP comes from the Exim mainlog or from Postfix over
// syslog, as src says. ok is false for an unknown kind.
func loginFromSyslog(kind string, src loginSource) (syslog, ok bool) {
	switch kind {
	case knownCustomerCpanel, knownCustomerWebmail:
		return false, true
	case knownCustomerFTP, knownCustomerIMAP, knownCustomerPOP:
		return true, true
	case knownCustomerSMTP:
		return bool(src), true
	}
	return false, false
}

// customerGroup is what one account holds from one login source. A full set
// trims its largest groups first, so a flood loses its own entries before
// anyone else's.
type customerGroup struct {
	syslog  bool
	account string
}

// knownCustomers remembers addresses that logged in successfully as a
// customer, with the last such login. Only real successes are noted, so an
// attacker who can only fail logins never enters the set. An IPv6 host is
// its /64: privacy addresses rotate inside it. Its mutex is a leaf: the
// infra lookup and store I/O run outside it.
type knownCustomers struct {
	now func() time.Time
	// isInfra reports addresses that are never stored. Set once before log
	// readers start.
	isInfra func(ip string) bool

	mu          sync.Mutex
	entries     map[netip.Addr]store.KnownCustomer
	groups      map[customerGroup]map[netip.Addr]struct{}
	syslogCount int                     // entries read from syslog
	stored      map[netip.Addr]struct{} // addresses loaded or handed to the writer
	dirty       map[netip.Addr]struct{} // to write at the next save
	deleted     map[string]struct{}     // stored keys to remove at the next save
}

func newKnownCustomers(now func() time.Time) *knownCustomers {
	return &knownCustomers{
		now:     now,
		entries: make(map[netip.Addr]store.KnownCustomer),
		groups:  make(map[customerGroup]map[netip.Addr]struct{}),
		stored:  make(map[netip.Addr]struct{}),
		dirty:   make(map[netip.Addr]struct{}),
		deleted: make(map[string]struct{}),
	}
}

func knownCustomerExpired(at, now time.Time) bool {
	return now.Sub(at) >= knownCustomerTTL
}

// customerKey is the key ip is stored under: the address, or for IPv6 its
// /64.
func customerKey(ip string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return networkKey(addr.Unmap()), true
}

func networkKey(addr netip.Addr) netip.Addr {
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().Addr()
	}
	return addr
}

// storedKey reports whether raw is a key as Changes writes it.
func storedKey(raw string) (netip.Addr, bool) {
	key, ok := customerKey(raw)
	return key, ok && key.String() == raw
}

// customerAddr is the key a login from ip is stored under, or false when ip
// can never be a customer address.
func (k *knownCustomers) customerAddr(ip string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || (k.isInfra != nil && k.isInfra(addr.String())) {
		return netip.Addr{}, false
	}
	return networkKey(addr), true
}

// Note records a successful login of kind from ip at at, read from src. A
// login older than the TTL is ignored and one stamped in the future counts
// as now.
func (k *knownCustomers) Note(ip, kind, account string, at time.Time, src loginSource) {
	if k == nil {
		return
	}
	syslog, ok := loginFromSyslog(kind, src)
	if !ok {
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
	c := store.KnownCustomer{Kind: kind, Account: strings.Clone(normalizeSprayMailbox(account)), At: at, Syslog: syslog}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.putLocked(addr, c, now)
}

// putLocked stores c for addr, then trims the half c belongs to. An expired
// entry counts as absent.
func (k *knownCustomers) putLocked(addr netip.Addr, c store.KnownCustomer, now time.Time) {
	if old, exists := k.entries[addr]; exists {
		if !knownCustomerExpired(old.At, now) {
			switch {
			case !old.Syslog && c.Syslog:
				// A forged syslog line would relabel the entry into the
				// half a syslog flood can trim.
				return
			case old.Syslog && !c.Syslog:
				// A service log is the stronger record; keep the later time.
				if old.At.After(c.At) {
					c.At = old.At
				}
			case old.At.After(c.At):
				return
			}
		}
		k.unlinkLocked(addr, old)
	}
	k.entries[addr] = c
	k.linkLocked(addr, c)
	k.dirty[addr] = struct{}{}
	delete(k.deleted, addr.String())
	k.trimGroupLocked(customerGroup{c.Syslog, c.Account})
	if c.Syslog && k.syslogCount > maxSyslogCustomers {
		k.evictLocked(true, k.syslogCount-(maxSyslogCustomers*95/100+1))
	}
	if service := len(k.entries) - k.syslogCount; !c.Syslog && service > maxServiceCustomers {
		k.evictLocked(false, service-(maxServiceCustomers*95/100+1))
	}
}

func (k *knownCustomers) linkLocked(addr netip.Addr, c store.KnownCustomer) {
	g := customerGroup{c.Syslog, c.Account}
	held := k.groups[g]
	if held == nil {
		held = make(map[netip.Addr]struct{})
		k.groups[g] = held
	}
	held[addr] = struct{}{}
	if c.Syslog {
		k.syslogCount++
	}
}

func (k *knownCustomers) unlinkLocked(addr netip.Addr, c store.KnownCustomer) {
	g := customerGroup{c.Syslog, c.Account}
	delete(k.groups[g], addr)
	if len(k.groups[g]) == 0 {
		delete(k.groups, g)
	}
	if c.Syslog {
		k.syslogCount--
	}
}

// trimGroupLocked drops the oldest entry of a group over its cap, which may
// be the one just noted.
func (k *knownCustomers) trimGroupLocked(g customerGroup) {
	held := k.groups[g]
	if len(held) <= maxKnownCustomerIPsPerAccount {
		return
	}
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

// evictLocked removes n entries of one half, each the oldest of the largest
// remaining group.
func (k *knownCustomers) evictLocked(syslog bool, n int) {
	byGroup := make(map[customerGroup][]customerEntry)
	for a, c := range k.entries {
		if c.Syslog == syslog {
			g := customerGroup{c.Syslog, c.Account}
			byGroup[g] = append(byGroup[g], customerEntry{a, c})
		}
	}
	h := make(evictionHeap, 0, len(byGroup))
	for _, members := range byGroup {
		slices.SortFunc(members, compareCustomerEntries)
		h = append(h, members)
	}
	heap.Init(&h)
	for ; n > 0 && h.Len() > 0; n-- {
		members := h[0]
		k.removeLocked(members[0].addr)
		if len(members) == 1 {
			heap.Pop(&h)
			continue
		}
		h[0] = members[1:]
		heap.Fix(&h, 0)
	}
}

// evictionHeap holds groups, oldest entry first within each, ordered largest
// group first and then by oldest entry.
type evictionHeap [][]customerEntry

func (h evictionHeap) Len() int { return len(h) }
func (h evictionHeap) Less(i, j int) bool {
	if len(h[i]) != len(h[j]) {
		return len(h[i]) > len(h[j])
	}
	return compareCustomerEntries(h[i][0], h[j][0]) < 0
}
func (h evictionHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *evictionHeap) Push(x any)   { *h = append(*h, x.([]customerEntry)) }
func (h *evictionHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

func (k *knownCustomers) removeLocked(addr netip.Addr) {
	c, ok := k.entries[addr]
	if !ok {
		return
	}
	delete(k.entries, addr)
	k.unlinkLocked(addr, c)
	delete(k.dirty, addr)
	if _, stored := k.stored[addr]; stored && !k.queueDeleteLocked(addr.String()) {
		delete(k.stored, addr)
	}
}

// queueDeleteLocked marks a stored key for deletion at the next save and
// reports whether it did. Pending deletes stay bounded; a key past the bound
// stays on disk until a later load drops it again.
func (k *knownCustomers) queueDeleteLocked(raw string) bool {
	if _, pending := k.deleted[raw]; !pending && len(k.deleted) >= maxKnownCustomers {
		return false
	}
	k.deleted[raw] = struct{}{}
	return true
}

// customerHit names an IPv6 entry by its /64.
func customerHit(addr netip.Addr, c store.KnownCustomer) blockdigest.CustomerHit {
	return blockdigest.CustomerHit{IP: customerHitIP(addr), Kind: c.Kind, Account: c.Account, At: c.At}
}

func customerHitIP(addr netip.Addr) string {
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).String()
	}
	return addr.String()
}

// entryPrefix is the network one entry covers.
func entryPrefix(addr netip.Addr) netip.Prefix {
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64)
	}
	return netip.PrefixFrom(addr, 32)
}

// Lookup returns the last customer login from ip, or from its IPv6 /64,
// within the TTL.
func (k *knownCustomers) Lookup(ip string) (blockdigest.CustomerHit, bool) {
	if k == nil {
		return blockdigest.CustomerHit{}, false
	}
	key, ok := customerKey(ip)
	if !ok {
		return blockdigest.CustomerHit{}, false
	}
	now := k.now()
	k.mu.Lock()
	c, ok := k.entries[key]
	k.mu.Unlock()
	if !ok || knownCustomerExpired(c.At, now) {
		return blockdigest.CustomerHit{}, false
	}
	return customerHit(key, c), true
}

// Within counts the known customers that p covers or overlaps and returns up
// to limit of them, the most recent first. An omitted customer counts toward
// neither the total nor the sample. omit must not take locks or perform I/O.
func (k *knownCustomers) Within(p netip.Prefix, limit int, omit func(blockdigest.CustomerHit) bool) (n int, sample []blockdigest.CustomerHit) {
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
		if !p.Overlaps(entryPrefix(addr)) || knownCustomerExpired(c.At, now) {
			continue
		}
		if omit != nil && omit(customerHit(addr, c)) {
			continue
		}
		n++
		if limit > 0 {
			matches = append(matches, customerEntry{addr, c})
		}
	}
	k.mu.Unlock()
	if limit <= 0 {
		return n, nil
	}
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

// Load merges saved entries, keeping the newer login per key. Saved keys it
// cannot use (unparsable, not a customer address, an unknown kind, past the
// TTL) or that are not keys as Changes writes them are queued for deletion,
// so the bucket sheds them.
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
		syslog, kindOK := loginFromSyslog(c.Kind, loginSource(c.Syslog))
		addr, ok := k.customerAddr(raw)
		if !kindOK || !ok || knownCustomerExpired(c.At, now) {
			dropped = append(dropped, raw)
			continue
		}
		if c.At.After(now) {
			c.At = now
		}
		c.Account = strings.Clone(normalizeSprayMailbox(c.Account))
		c.Syslog = syslog
		valid = append(valid, entry{raw, addr, c})
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, raw := range dropped {
		k.queueDeleteLocked(raw)
	}
	// Index all stored keys before admission: a later record may evict an
	// earlier one, and both still need deletion from the saved set.
	for _, e := range valid {
		if e.raw == e.addr.String() {
			k.stored[e.addr] = struct{}{}
		}
	}
	slices.SortFunc(valid, func(a, b entry) int {
		return compareCustomerEntries(customerEntry{a.addr, a.c}, customerEntry{b.addr, b.c})
	})
	for _, e := range valid {
		canonical := e.raw == e.addr.String()
		if !canonical {
			k.queueDeleteLocked(e.raw)
		}
		k.putLocked(e.addr, e.c, now)
		// The store already holds an entry loaded unchanged.
		if cur, ok := k.entries[e.addr]; ok && canonical && sameKnownCustomer(cur, saved[e.raw]) {
			delete(k.dirty, e.addr)
		}
	}
}

func sameKnownCustomer(a, b store.KnownCustomer) bool {
	return a.Kind == b.Kind && a.Account == b.Account && a.At.Equal(b.At) && a.Syslog == b.Syslog
}

// Changes returns what changed since the last call: entries to write and
// stored keys to delete.
func (k *knownCustomers) Changes() (upserts map[string]store.KnownCustomer, deletes []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	upserts = make(map[string]store.KnownCustomer, len(k.dirty))
	for addr := range k.dirty {
		upserts[addr.String()] = k.entries[addr]
		k.stored[addr] = struct{}{}
	}
	deletes = make([]string, 0, len(k.deleted))
	for raw := range k.deleted {
		deletes = append(deletes, raw)
		if addr, ok := storedKey(raw); ok {
			delete(k.stored, addr)
		}
	}
	slices.Sort(deletes)
	clear(k.dirty)
	clear(k.deleted)
	return upserts, deletes
}

// requeue marks the keys of a failed save for the next one: a key still held
// is written with its current value, any other is deleted.
func (k *knownCustomers) requeue(upserts map[string]store.KnownCustomer, deletes []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	mark := func(raw string) {
		addr, isKey := storedKey(raw)
		if isKey {
			if _, ok := k.entries[addr]; ok {
				k.stored[addr] = struct{}{}
				k.dirty[addr] = struct{}{}
				return
			}
		}
		queued := k.queueDeleteLocked(raw)
		if !isKey {
			return
		}
		if queued {
			// A failed delete may still be on disk even if a new login
			// temporarily cancels this pending deletion.
			k.stored[addr] = struct{}{}
		} else {
			delete(k.stored, addr)
		}
	}
	for raw := range upserts {
		mark(raw)
	}
	for _, raw := range deletes {
		mark(raw)
	}
}

// customerLoginTime keeps buffered records from renewing an old login.
// Timestamp-free journal messages use the receipt time.
func customerLoginTime(line string, now time.Time) time.Time {
	if strings.HasPrefix(line, "[") {
		if end := strings.IndexByte(line, ']'); end > 0 {
			if at, err := time.Parse("2006-01-02 15:04:05 -0700", line[1:end]); err == nil {
				return at
			}
		}
	}
	if at := smtpAuthLogTime(line, now); !at.IsZero() {
		return at
	}
	if len(line) >= len("2006-01-02 15:04:05") {
		if at, err := time.ParseInLocation("2006-01-02 15:04:05", line[:len("2006-01-02 15:04:05")], now.Location()); err == nil {
			return at
		}
	}
	return now
}

// noteFTPCustomers remembers the addresses of successful FTP logins.
func (d *Daemon) noteFTPCustomers(findings []alert.Finding) {
	for _, f := range findings {
		switch f.Check {
		case "ftp_login", "ftp_login_after_bruteforce":
			d.knownCustomers.Note(f.SourceIP, knownCustomerFTP, ftpCustomerAccount(f), f.Timestamp, syslogFed)
		}
	}
}

// ftpCustomerAccount is the account an FTP login is known under: the hosting
// account that owns the FTP account, or the login name when no account owns
// it.
func ftpCustomerAccount(f alert.Finding) string {
	if f.TenantID != "" {
		return f.TenantID
	}
	if f.LoginAccount != "" {
		return f.LoginAccount
	}
	return checks.FTPLoginAccount(f.Details)
}

// loadKnownCustomers seeds the set from the last run. The store still
// returns the records when it could not delete the unusable ones.
func (d *Daemon) loadKnownCustomers() {
	sdb := store.Global()
	if sdb == nil {
		return
	}
	saved, err := sdb.LoadKnownCustomers()
	if err != nil {
		csmlog.Warn("known customer load failed", "err", err)
	}
	d.knownCustomers.Load(saved)
}

// persistKnownCustomers purges expired entries and saves what changed.
func (d *Daemon) persistKnownCustomers() {
	if d.knownCustomers == nil {
		return
	}
	d.knownCustomers.Purge()
	sdb := store.Global()
	if sdb == nil {
		return
	}
	upserts, deletes := d.knownCustomers.Changes()
	if len(upserts)+len(deletes) == 0 {
		return
	}
	if err := sdb.SaveKnownCustomers(upserts, deletes); err != nil {
		d.knownCustomers.requeue(upserts, deletes)
		csmlog.Warn("known customer save failed", "err", err)
	}
}

// runKnownCustomers saves the set every minute. The last save runs in the
// shutdown flush, once log readers and dispatch have stopped noting logins.
func (d *Daemon) runKnownCustomers() {
	defer d.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-t.C:
			d.persistKnownCustomers()
		}
	}
}
