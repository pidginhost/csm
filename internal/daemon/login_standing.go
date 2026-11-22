package daemon

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
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

// standingRow is one address's trusted logins to one mailbox, in Unix
// seconds: the first, and the earliest of each of its latest dates,
// ascending. first is never after days[0].
type standingRow struct {
	first int64
	days  []int64
}

func (r *standingRow) latest() int64 { return r.days[len(r.days)-1] }

// add records a success; a date keeps its earliest.
func (r *standingRow) add(sec int64) {
	r.first = min(r.first, sec)
	i, found := slices.BinarySearchFunc(r.days, sec/secondsPerDay, func(d, day int64) int {
		return cmp.Compare(d/secondsPerDay, day)
	})
	if found {
		r.days[i] = min(r.days[i], sec)
		return
	}
	r.days = slices.Insert(r.days, i, sec)
	if extra := len(r.days) - standingDays; extra > 0 {
		r.days = slices.Delete(r.days, 0, extra)
	}
}

// standingAt applies the rule as of asOf: successes at or after it never
// count, so a login after an attack began cannot excuse that attack.
func (r *standingRow) standingAt(asOf int64) bool {
	if asOf-r.first < int64(standingFirstAge/time.Second) {
		return false
	}
	dates, lastDay, latest := 1, r.first/secondsPerDay, r.first
	for _, d := range r.days {
		if d >= asOf {
			break
		}
		if day := d / secondsPerDay; day != lastDay {
			dates++
			lastDay = day
		}
		latest = d
	}
	return dates >= 2 && asOf-latest <= int64(standingRecent/time.Second)
}

func (r *standingRow) export() store.LoginStanding {
	return store.LoginStanding{First: r.first, Days: slices.Clone(r.days)}
}

// loginStanding remembers trusted clean logins per address and mailbox, so
// a customer's device retrying an old password is told apart from an
// attack. Only the trackers' trusted logins feed it. Its mutex is a leaf:
// logging and store I/O run outside it. Every method is a no-op on nil.
type loginStanding struct {
	now func() time.Time

	mu        sync.Mutex
	rows      map[standingKey]*standingRow
	byMailbox map[string]map[netip.Addr]struct{}
	dirty     map[standingKey]struct{} // to write at the next save
	deleted   map[string]struct{}      // store keys to remove at the next save
	replace   bool                     // the next save rewrites the bucket
	nextPrune time.Time                // a full index prunes at most once a minute
	warnedAt  time.Time                // the full-index warning repeats at most hourly
}

func newLoginStanding(now func() time.Time) *loginStanding {
	return &loginStanding{
		now:       now,
		rows:      make(map[standingKey]*standingRow),
		byMailbox: make(map[string]map[netip.Addr]struct{}),
		dirty:     make(map[standingKey]struct{}),
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
		r = &standingRow{first: sec}
		s.rows[k] = r
		held := s.byMailbox[k.mailbox]
		if held == nil {
			held = make(map[netip.Addr]struct{})
			s.byMailbox[k.mailbox] = held
		}
		held[k.addr] = struct{}{}
	}
	r.add(sec)
	s.dirty[k] = struct{}{}
	delete(s.deleted, k.String())
	return false
}

// roomLocked makes room for a new row on mailbox: a full mailbox drops its
// row with the oldest latest success; a full index prunes expired rows and
// otherwise refuses.
func (s *loginStanding) roomLocked(mailbox string, now time.Time) bool {
	if held := s.byMailbox[mailbox]; len(held) >= maxStandingPerMailbox {
		var victim netip.Addr
		var oldest int64
		for addr := range held {
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
	for addr := range s.byMailbox[mailbox] {
		s.removeLocked(standingKey{addr, mailbox})
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
		delete(held, k.addr)
		if len(held) == 0 {
			delete(s.byMailbox, k.mailbox)
		}
	}
	delete(s.dirty, k)
	s.queueDeleteLocked(k.String())
}

// queueDeleteLocked marks a store key for deletion. Past the bound the next
// save rewrites the bucket instead, so no removal is ever lost.
func (s *loginStanding) queueDeleteLocked(raw string) {
	if s.replace {
		return
	}
	s.deleted[raw] = struct{}{}
	if len(s.deleted) >= maxStandingRows {
		s.replace = true
		clear(s.deleted)
	}
}

// Load merges saved rows. A key or row it cannot trust is dropped and
// queued for deletion; valid rows are admitted newest first while both
// caps allow.
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
		if c := cmp.Compare(b.row.Days[len(b.row.Days)-1], a.row.Days[len(a.row.Days)-1]); c != 0 {
			return c
		}
		return cmp.Compare(a.key.String(), b.key.String())
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, raw := range dropped {
		s.queueDeleteLocked(raw)
	}
	for _, e := range valid {
		if r := s.rows[e.key]; r != nil {
			// Logins noted before the load keep their row; the saved
			// history joins it.
			for _, d := range e.row.Days {
				r.add(d)
			}
			r.first = min(r.first, e.row.First)
			s.dirty[e.key] = struct{}{}
			continue
		}
		if len(s.rows) >= maxStandingRows || len(s.byMailbox[e.key.mailbox]) >= maxStandingPerMailbox {
			s.queueDeleteLocked(e.key.String())
			continue
		}
		s.rows[e.key] = &standingRow{first: e.row.First, days: slices.Clone(e.row.Days)}
		held := s.byMailbox[e.key.mailbox]
		if held == nil {
			held = make(map[netip.Addr]struct{})
			s.byMailbox[e.key.mailbox] = held
		}
		held[e.key.addr] = struct{}{}
	}
}

// validStandingRow reports whether a saved row is one Note could have
// written and still within the row window.
func validStandingRow(row store.LoginStanding, now, cutoff int64) bool {
	if len(row.Days) == 0 || len(row.Days) > standingDays || row.First <= 0 ||
		row.Days[0] < row.First || row.Days[len(row.Days)-1] > now || row.Days[len(row.Days)-1] < cutoff {
		return false
	}
	for i := 1; i < len(row.Days); i++ {
		if row.Days[i]/secondsPerDay <= row.Days[i-1]/secondsPerDay {
			return false
		}
	}
	return true
}

// Changes returns what changed since the last call: rows to write and store
// keys to delete, or, with replace, every row to replace the bucket with.
func (s *loginStanding) Changes() (upserts map[string]store.LoginStanding, deletes []string, replace bool) {
	if s == nil {
		return nil, nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		clear(s.dirty)
		clear(s.deleted)
		s.replace = false
	}()
	if s.replace {
		upserts = make(map[string]store.LoginStanding, len(s.rows))
		for k, r := range s.rows {
			upserts[k.String()] = r.export()
		}
		return upserts, nil, true
	}
	upserts = make(map[string]store.LoginStanding, len(s.dirty))
	for k := range s.dirty {
		upserts[k.String()] = s.rows[k].export()
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
	if replace {
		s.replace = true
		return
	}
	mark := func(raw string) {
		if k, ok := parseStandingKey(raw); ok && s.rows[k] != nil {
			s.dirty[k] = struct{}{}
			delete(s.deleted, raw)
			return
		}
		s.queueDeleteLocked(raw)
	}
	for raw := range upserts {
		mark(raw)
	}
	for _, raw := range deletes {
		mark(raw)
	}
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
