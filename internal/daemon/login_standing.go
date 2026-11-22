package daemon

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/store"
)

// An address has login standing on a mailbox when its trusted logins there
// began at least standingFirstAge before an attack, fall on two UTC dates
// before it, and the latest of them is within standingRecent of it.
const (
	standingFirstAge = 24 * time.Hour
	standingRecent   = 14 * 24 * time.Hour
	// standingDays bounds the dates a row keeps, and a row whose latest
	// success is older than that many days is dropped.
	standingDays = 15
)

// The index is bounded: a full mailbox replaces its own least recently used
// row, and a full index refuses new rows rather than evicting live ones. A
// missing row is no standing, so filling the index never stops a block.
const (
	maxStandingRows       = 100000
	maxStandingPerMailbox = 256
)

const (
	secondsPerDay = int64(24 * time.Hour / time.Second)
	standingKeep  = standingDays * 24 * time.Hour
)

// standingKey is one address, exact for IPv6 and folded for mapped IPv4,
// and one mailbox in normalizeSprayMailbox's spelling.
type standingKey struct {
	addr    netip.Addr
	mailbox string
}

func (k standingKey) String() string { return k.addr.String() + " " + k.mailbox }

// A date needs both ends: its first login proves it preceded asOf, while
// its last login determines recency when the whole date precedes asOf.
type standingDay struct {
	first int64
	last  int64
}

// standingRow keeps the original first success and the endpoints of its
// latest dates. mailbox owns its storage, independent of input log lines.
type standingRow struct {
	first   int64
	days    []standingDay
	mailbox string
	dirty   bool
}

func (r *standingRow) latest() int64 { return r.days[len(r.days)-1].last }

func (r *standingRow) add(sec int64) {
	r.first = min(r.first, sec)
	i, found := slices.BinarySearchFunc(r.days, sec/secondsPerDay, func(d standingDay, day int64) int {
		return cmp.Compare(d.first/secondsPerDay, day)
	})
	if found {
		r.days[i].first = min(r.days[i].first, sec)
		r.days[i].last = max(r.days[i].last, sec)
		return
	}
	if len(r.days) == standingDays {
		if i == 0 {
			return
		}
		r.days = slices.Delete(r.days, 0, 1)
		i--
	}
	// Never grow beyond the retained dates when inserting into a full row.
	if len(r.days) == cap(r.days) {
		days := make([]standingDay, len(r.days), min(standingDays, max(1, 2*cap(r.days))))
		copy(days, r.days)
		r.days = days
	}
	r.days = slices.Insert(r.days, i, standingDay{sec, sec})
}

// standingAt applies the rule as of asOf: successes at or after it never
// count, so a login after an attack began cannot excuse that attack.
func (r *standingRow) standingAt(asOf int64) bool {
	if asOf-r.first < int64(standingFirstAge/time.Second) {
		return false
	}
	dates, lastDay, latest := 1, r.first/secondsPerDay, r.first
	for _, d := range r.days {
		if d.first >= asOf {
			break
		}
		if day := d.first / secondsPerDay; day != lastDay {
			dates++
			lastDay = day
		}
		latest = d.first
		if d.last < asOf {
			latest = d.last
		}
		// If asOf splits this date, its first success already proves
		// recency. No later success on the date needs to be counted.
	}
	return dates >= 2 && asOf-latest <= int64(standingRecent/time.Second)
}

func (r *standingRow) export() store.LoginStanding {
	row := store.LoginStanding{First: r.first, Days: make([]int64, len(r.days))}
	for i, d := range r.days {
		row.Days[i] = d.first
		if d.last != d.first && row.Lasts == nil {
			row.Lasts = make([]int64, len(r.days))
			copy(row.Lasts, row.Days)
		}
		if row.Lasts != nil {
			row.Lasts[i] = d.last
		}
	}
	return row
}

// loginStanding remembers trusted clean logins per address and mailbox, so
// a customer's device retrying an old password is told apart from an
// attack. Only the trackers' trusted logins feed it. Its mutex is a leaf:
// logging and store I/O run outside it. Every method is a no-op on nil.
type loginStanding struct {
	now func() time.Time

	mu          sync.Mutex
	initialized bool // a snapshot may only initialize an unused index
	rows        map[standingKey]*standingRow
	byMailbox   map[string][]netip.Addr
	deleted     map[string]struct{} // store keys to remove at the next save
	replace     bool                // the next save rewrites the bucket
	nextPrune   time.Time           // a full index prunes at most once a minute
	warnedAt    time.Time           // the full-index warning repeats at most hourly
}

func newLoginStanding(now func() time.Time) *loginStanding {
	return &loginStanding{
		now:       now,
		rows:      make(map[standingKey]*standingRow),
		byMailbox: make(map[string][]netip.Addr),
		deleted:   make(map[string]struct{}),
	}
}

// standingAddr is the address standing is kept under: exact, with mapped
// IPv4 folded. A /64 can hold other tenants of a provider.
func standingAddr(ip string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// parseStandingKey reads a store key as String writes it.
func parseStandingKey(raw string) (standingKey, bool) {
	text, mailbox, ok := strings.Cut(raw, " ")
	if !ok || mailbox == "" || normalizeSprayMailbox(mailbox) != mailbox {
		return standingKey{}, false
	}
	addr, err := netip.ParseAddr(text)
	if err != nil || addr.Zone() != "" || addr.Unmap().String() != text {
		return standingKey{}, false
	}
	return standingKey{addr.Unmap(), mailbox}, true
}

// Note records a trusted clean login to mailbox from ip at at. A login
// stamped in the future counts as now; one older than the row window is
// ignored.
func (s *loginStanding) Note(ip, mailbox string, at time.Time) {
	if s == nil {
		return
	}
	addr, ok := standingAddr(ip)
	mailbox = normalizeSprayMailbox(mailbox)
	if !ok || mailbox == "" {
		return
	}
	now := s.now()
	if at.After(now) {
		at = now
	}
	if now.Sub(at) > standingKeep {
		return
	}
	if s.note(standingKey{addr, mailbox}, at.Unix(), now) {
		csmlog.Warn("login standing index full; new rows refused until old ones expire", "rows", maxStandingRows)
	}
}

// note reports whether a refused row should be logged.
func (s *loginStanding) note(k standingKey, sec int64, now time.Time) (warn bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized = true
	r := s.rows[k]
	if r == nil {
		if !s.roomLocked(k.mailbox, now) {
			if now.Sub(s.warnedAt) < time.Hour {
				return false
			}
			s.warnedAt = now
			return true
		}
		// A mailbox name may be a slice of a long log line.
		k.mailbox = strings.Clone(k.mailbox)
		r = &standingRow{first: sec, mailbox: k.mailbox}
		s.rows[k] = r
		s.byMailbox[k.mailbox] = append(s.byMailbox[k.mailbox], k.addr)
	}
	r.add(sec)
	r.dirty = true
	delete(s.deleted, k.String())
	s.boundDeletesLocked()
	return false
}

// roomLocked makes room for a new row on mailbox: a full mailbox drops its
// row with the oldest latest success; a full index prunes expired rows and
// otherwise refuses.
func (s *loginStanding) roomLocked(mailbox string, now time.Time) bool {
	if held := s.byMailbox[mailbox]; len(held) >= maxStandingPerMailbox {
		var victim netip.Addr
		var oldest int64
		for _, addr := range held {
			latest := s.rows[standingKey{addr, mailbox}].latest()
			if !victim.IsValid() || latest < oldest || latest == oldest && addr.Less(victim) {
				victim, oldest = addr, latest
			}
		}
		s.removeLocked(standingKey{victim, mailbox})
	}
	if len(s.rows) < maxStandingRows {
		return true
	}
	if !now.Before(s.nextPrune) {
		s.nextPrune = now.Add(time.Minute)
		s.pruneLocked(now)
	}
	return len(s.rows) < maxStandingRows
}

// Has reports whether ip had standing on mailbox as of asOf, the start of
// the failures being judged. A zero asOf is no standing.
func (s *loginStanding) Has(ip, mailbox string, asOf time.Time) bool {
	if s == nil || asOf.IsZero() {
		return false
	}
	addr, ok := standingAddr(ip)
	mailbox = normalizeSprayMailbox(mailbox)
	if !ok || mailbox == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rows[standingKey{addr, mailbox}]
	return r != nil && r.standingAt(asOf.Unix())
}

// Revoke drops every address's standing on mailbox, when the mailbox is
// found cracked or suspended: an attacker may have earned standing there
// before being caught.
func (s *loginStanding) Revoke(mailbox string) {
	if s == nil {
		return
	}
	mailbox = normalizeSprayMailbox(mailbox)
	if mailbox == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized = true
	// removeLocked compacts the address slice, so consume it from the end.
	for held := s.byMailbox[mailbox]; len(held) > 0; held = s.byMailbox[mailbox] {
		s.removeLocked(standingKey{held[len(held)-1], mailbox})
	}
}

// Purge drops rows with no success in the row window.
func (s *loginStanding) Purge() {
	if s == nil {
		return
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized = true
	s.pruneLocked(now)
}

func (s *loginStanding) pruneLocked(now time.Time) {
	cutoff := now.Add(-standingKeep).Unix()
	for k, r := range s.rows {
		if r.latest() < cutoff {
			s.removeLocked(k)
		}
	}
}

// Len returns the number of rows.
func (s *loginStanding) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rows)
}

func (s *loginStanding) removeLocked(k standingKey) {
	if _, ok := s.rows[k]; !ok {
		return
	}
	delete(s.rows, k)
	if held := s.byMailbox[k.mailbox]; held != nil {
		i := slices.Index(held, k.addr)
		held = slices.Delete(held, i, i+1)
		if len(held) == 0 {
			delete(s.byMailbox, k.mailbox)
		} else {
			// Keep the owned mailbox spelling when the map replaces its key.
			mailbox := s.rows[standingKey{held[0], k.mailbox}].mailbox
			s.byMailbox[mailbox] = held
		}
	}
	s.queueDeleteLocked(k.String())
}

// maxStandingPendingDeletes bounds the store keys waiting for deletion
// between saves. Steady churn at the row cap stays far below it, so saves
// stay incremental; past it the next save rewrites the bucket, so no
// removal is lost.
const maxStandingPendingDeletes = 8192

// queueDeleteLocked marks a store key for deletion.
func (s *loginStanding) queueDeleteLocked(raw string) {
	if s.replace {
		return
	}
	s.deleted[raw] = struct{}{}
	s.boundDeletesLocked()
}

func (s *loginStanding) boundDeletesLocked() {
	if len(s.deleted) > maxStandingPendingDeletes {
		s.replace = true
		clear(s.deleted)
	}
}

// Load initializes an unused index from a startup snapshot. Call it before
// Note, Revoke, Purge or Changes; later loads only queue the current state
// for saving, so stale snapshots cannot undo updates or revocations. Invalid
// rows are queued for deletion; valid rows enter newest first within the caps.
func (s *loginStanding) Load(saved map[string]store.LoginStanding) {
	if s == nil {
		return
	}
	type entry struct {
		key standingKey
		row store.LoginStanding
	}
	now := s.now()
	cutoff := now.Add(-standingKeep).Unix()
	valid := make([]entry, 0, len(saved))
	var dropped []string
	for raw, row := range saved {
		k, ok := parseStandingKey(raw)
		if !ok || !validStandingRow(row, now.Unix(), cutoff) {
			dropped = append(dropped, raw)
			continue
		}
		valid = append(valid, entry{k, row})
	}
	slices.SortFunc(valid, func(a, b entry) int {
		if c := cmp.Compare(standingSavedLatest(b.row), standingSavedLatest(a.row)); c != 0 {
			return c
		}
		return cmp.Compare(a.key.String(), b.key.String())
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.initialized {
		for raw := range saved {
			s.markCurrentLocked(raw)
		}
		return
	}
	s.initialized = true
	for _, raw := range dropped {
		s.queueDeleteLocked(raw)
	}
	for _, e := range valid {
		if len(s.rows) >= maxStandingRows || len(s.byMailbox[e.key.mailbox]) >= maxStandingPerMailbox {
			s.queueDeleteLocked(e.key.String())
			continue
		}
		e.key.mailbox = strings.Clone(e.key.mailbox)
		r := &standingRow{first: e.row.First, mailbox: e.key.mailbox, days: make([]standingDay, len(e.row.Days))}
		for i, first := range e.row.Days {
			last := first
			if len(e.row.Lasts) != 0 {
				last = e.row.Lasts[i]
			}
			r.days[i] = standingDay{first, last}
		}
		s.rows[e.key] = r
		s.byMailbox[e.key.mailbox] = append(s.byMailbox[e.key.mailbox], e.key.addr)
	}
	s.boundDeletesLocked()
}

func standingSavedLatest(row store.LoginStanding) int64 {
	if len(row.Lasts) != 0 {
		return row.Lasts[len(row.Lasts)-1]
	}
	return row.Days[len(row.Days)-1]
}

// validStandingRow reports whether a saved row is one Note could have
// written and still within the row window.
func validStandingRow(row store.LoginStanding, now, cutoff int64) bool {
	if len(row.Days) == 0 || len(row.Days) > standingDays || row.First <= 0 ||
		row.Days[0] < row.First || (len(row.Lasts) != 0 && len(row.Lasts) != len(row.Days)) {
		return false
	}
	if latest := standingSavedLatest(row); latest > now || latest < cutoff {
		return false
	}
	for i, first := range row.Days {
		if i > 0 && first/secondsPerDay <= row.Days[i-1]/secondsPerDay {
			return false
		}
		if len(row.Lasts) != 0 && (row.Lasts[i] < first || row.Lasts[i]/secondsPerDay != first/secondsPerDay) {
			return false
		}
	}
	return true
}

// Changes returns what changed since the last call: rows to write and store
// keys to delete, or, with replace, every row to replace the bucket with.
// The caller must serialize extraction, the store write, and requeue on failure.
func (s *loginStanding) Changes() (upserts map[string]store.LoginStanding, deletes []string, replace bool) {
	if s == nil {
		return nil, nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized = true
	defer func() {
		clear(s.deleted)
		s.replace = false
	}()
	upserts = make(map[string]store.LoginStanding)
	// Scanning the bounded rows avoids a second map of full address/mailbox
	// keys, which is expensive when every row belongs to a different mailbox.
	for k, r := range s.rows {
		if s.replace || r.dirty {
			upserts[k.String()] = r.export()
			r.dirty = false
		}
	}
	if s.replace {
		return upserts, nil, true
	}
	deletes = make([]string, 0, len(s.deleted))
	for raw := range s.deleted {
		deletes = append(deletes, raw)
	}
	slices.Sort(deletes)
	return upserts, deletes, false
}

// requeue marks the keys of a failed save for the next one: a row still
// held is written with its current value, any other key is deleted.
func (s *loginStanding) requeue(upserts map[string]store.LoginStanding, deletes []string, replace bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized = true
	if replace {
		s.replace = true
		return
	}
	for raw := range upserts {
		s.markCurrentLocked(raw)
	}
	for _, raw := range deletes {
		s.markCurrentLocked(raw)
	}
}

func (s *loginStanding) markCurrentLocked(raw string) {
	if k, ok := parseStandingKey(raw); ok && s.rows[k] != nil {
		s.rows[k].dirty = true
		delete(s.deleted, raw)
		return
	}
	s.queueDeleteLocked(raw)
}

// standingConfined reports whether every mailbox in accounts is one ip had
// standing on as of asOf, the start of the failures, and no failure went
// unvouched: one naming no mailbox or one the bounded map could not hold.
func standingConfined(s *loginStanding, ip string, accounts map[string]time.Time, unvouched, asOf time.Time) bool {
	if s == nil || len(accounts) == 0 || !unvouched.IsZero() {
		return false
	}
	for account := range accounts {
		if !s.Has(ip, account, asOf) {
			return false
		}
	}
	return true
}

// loginStandingAdvisory is the visible finding a brute-force block becomes
// when every failing mailbox is one the address has login standing on.
func loginStandingAdvisory(service, ip, burst, targets string, now time.Time) alert.Finding {
	details := "Every failing mailbox is one this address has login standing on: trusted logins on more than one day before these failures began, so this is likely a device with an old saved password. Visibility only - no auto-block; spray and compromise detectors remain active."
	if targets != "" {
		details += " " + targets + "."
	}
	return alert.Finding{
		Severity:  alert.High,
		Check:     "mail_bruteforce_suspected",
		Message:   fmt.Sprintf("Suspected stale %s password from %s: %s, only on mailboxes it has login standing on (not auto-blocked)", service, ip, burst),
		Details:   details,
		Timestamp: now,
		SourceIP:  ip,
	}
}

// formatStandingTargets names the mailboxes of a bounded failure map, at
// most maxMailTargetsListed of them.
func formatStandingTargets(accounts map[string]time.Time) string {
	if len(accounts) == 0 {
		return ""
	}
	names := slices.Sorted(maps.Keys(accounts))
	listed := names[:min(len(names), maxMailTargetsListed)]
	var b strings.Builder
	b.WriteString("Targets: ")
	for i, name := range listed {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(formatMailFailTargetAccount(name))
	}
	if extra := len(names) - len(listed); extra > 0 {
		fmt.Fprintf(&b, " (+%d more)", extra)
	}
	return b.String()
}

// mailboxResponseStanding is the index mailbox response withdraws standing
// from. New sets it.
var mailboxResponseStanding atomic.Pointer[loginStanding]

// loadLoginStanding restores the standing the last run saved. It runs before
// log readers start: the index takes a snapshot only before its first use.
func (d *Daemon) loadLoginStanding() {
	if d.loginStanding == nil {
		return
	}
	sdb := store.Global()
	if sdb == nil {
		return
	}
	saved, err := sdb.LoadLoginStanding()
	if err != nil {
		csmlog.Warn("login standing load failed", "err", err)
	}
	d.loginStanding.Load(saved)
}

// persistLoginStanding drops expired rows and saves what changed. The minute
// saver and the shutdown flush can overlap, and a failed save must be
// retried from current state, so one save runs at a time.
func (d *Daemon) persistLoginStanding() {
	if d.loginStanding == nil {
		return
	}
	d.loginStandingSaveMu.Lock()
	defer d.loginStandingSaveMu.Unlock()
	d.loginStanding.Purge()
	sdb := store.Global()
	if sdb == nil {
		return
	}
	upserts, deletes, replace := d.loginStanding.Changes()
	if len(upserts)+len(deletes) == 0 && !replace {
		return
	}
	if err := sdb.SaveLoginStanding(upserts, deletes, replace); err != nil {
		d.loginStanding.requeue(upserts, deletes, replace)
		csmlog.Warn("login standing save failed", "err", err)
	}
}
