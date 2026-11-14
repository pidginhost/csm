package attackdb

import (
	"bytes"
	"cmp"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
)

// mailReportEvery is the least time between two eviction reports.
const mailReportEvery = 24 * time.Hour

// Eviction reports spam-evidence records dropped to keep the budget.
type Eviction struct {
	Dropped        int    // records dropped since the last report
	Network        string // covering network with the most such records when the pass began
	NetworkRecords int    // how many it held
}

// SetMailBudget sets how many records the database keeps only for spam
// evidence. Zero or less means no limit.
func (db *DB) SetMailBudget(n int) {
	db.mu.Lock()
	db.mailBudget = n
	db.mu.Unlock()
}

// coveringNetwork is the network a record shares with its likely
// co-senders: the /48 around an IPv6 record, the /16 around an IPv4 one.
func coveringNetwork(key string) netip.Prefix {
	var addr netip.Addr
	if isNetworkKey(key) {
		network, _ := netip.ParsePrefix(key)
		addr = network.Addr()
	} else {
		addr, _ = netip.ParseAddr(key)
	}
	addr = addr.Unmap()
	bits := 48
	if addr.Is4() {
		bits = 16
	}
	return netip.PrefixFrom(addr, bits).Masked()
}

// Count records that can become mail-only, including stored login evidence
// without events. Its protection can expire between passes, so excluding it
// here would let the running count fall below the eligible population.
func (db *DB) recountMailOnlyLocked() {
	db.mailOnlyCount = 0
	db.mailAuthTimes = db.mailAuthTimes[:0]
	for _, rec := range db.records {
		if rec.Mail == nil || rec.EventCount != 0 || rec.AutoBlocked {
			continue
		}
		db.mailOnlyCount++
		if rec.Mail.AuthAttacks > 0 {
			db.mailAuthTimes = append(db.mailAuthTimes, rec.Mail.LastAuthAttack)
		}
	}
	slices.SortFunc(db.mailAuthTimes, time.Time.Compare)
}

// Subtract still-protected records without scanning the database on each
// verdict. A sorted clock index also handles verdicts arriving out of order.
func (db *DB) mailCountAtLocked(at time.Time) int {
	firstProtected := sort.Search(len(db.mailAuthTimes), func(i int) bool {
		return at.Sub(db.mailAuthTimes[i]) <= mailAuthWindow
	})
	return db.mailOnlyCount - (len(db.mailAuthTimes) - firstProtected)
}

func (db *DB) uncountMailLocked(rec *IPRecord) {
	if rec.Mail == nil || rec.EventCount != 0 || rec.AutoBlocked {
		return
	}
	db.mailOnlyCount--
	if rec.Mail.AuthAttacks > 0 {
		// On a miss the index is left as it is until the next recount.
		if i, found := slices.BinarySearchFunc(db.mailAuthTimes, rec.Mail.LastAuthAttack, time.Time.Compare); found {
			db.mailAuthTimes = slices.Delete(db.mailAuthTimes, i, i+1)
		}
	}
}

// mailLevel is the evidence level of m at the time its masses are decayed
// to: the mass in whole verdicts, rounded up, at least 1. Two counted
// verdicts hold level 2 however far they decayed, so senders of one message
// each never outrank a sender seen twice.
func mailLevel(m *MailEvidence) float64 {
	least := 1.0
	if m.Spam >= 2 || m.Ham >= 2 || m.Spam == 1 && m.Ham == 1 {
		least = 2
	}
	return max(least, math.Ceil(m.SpamMass+m.HamMass))
}

// evictMailLocked counts the mail-only records at at and, if they are over
// the budget, drops the weakest until nine tenths of it are left, so a flood
// pays for one pass per tenth of the budget and not per message.
//
// The weakest are those of the lowest evidence level. Inside a level the
// record whose covering network holds the most mail-only records goes
// first, then the one of the lowest mass, then the smallest key. So a
// record goes only when none of a lower level is left, and among equals a
// sender spread over one network pays before anyone else. A crowd never
// outranks a level: a network with many strong senders keeps them while
// weaker records are left. A pass always trims to nine tenths, so senders
// of one message each remove no record with two or more verdicts while such
// records fill less than nine tenths of the budget; above that, one pass
// trims the weakest of them once.
//
// It returns a report at most once in mailReportEvery. The caller holds
// db.mu.
func (db *DB) evictMailLocked(at time.Time) *Eviction {
	defer db.recountMailOnlyLocked()
	type candidate struct {
		key     string
		network netip.Prefix
		crowd   int
		level   float64
		mass    float64
	}
	all := make([]candidate, 0, db.mailOnlyCount)
	crowds := make(map[netip.Prefix]int)
	for key, rec := range db.records {
		if !mailOnly(rec, at) {
			continue
		}
		// A copy: the pass ranks evidence and must not change what is stored.
		m := *rec.Mail
		decayTo(&m, at)
		network := coveringNetwork(key)
		crowds[network]++
		all = append(all, candidate{key: key, network: network, level: mailLevel(&m), mass: m.SpamMass + m.HamMass})
	}
	if len(all) <= db.mailBudget {
		return nil
	}

	for i := range all {
		all[i].crowd = crowds[all[i].network]
	}
	slices.SortFunc(all, func(a, b candidate) int {
		if c := cmp.Compare(a.level, b.level); c != 0 {
			return c
		}
		if a.crowd != b.crowd {
			return b.crowd - a.crowd
		}
		if c := cmp.Compare(a.mass, b.mass); c != 0 {
			return c
		}
		return strings.Compare(a.key, b.key)
	})
	dropped := len(all) - db.mailBudget*9/10
	for _, c := range all[:dropped] {
		delete(db.records, c.key)
		db.markDeletedLocked(c.key)
	}
	db.mailEvicted += dropped
	db.mailEvictPending += dropped
	if !db.mailEvictReport.IsZero() && at.Sub(db.mailEvictReport) < mailReportEvery {
		return nil
	}
	// Prefix text is needed only for a report. Append into stack buffers to
	// keep a wide sender spread from allocating one string per network.
	var report Eviction
	var best, scratch [64]byte
	bestLen := 0
	for network, n := range crowds {
		text := network.AppendTo(scratch[:0])
		if n > report.NetworkRecords || n == report.NetworkRecords && bytes.Compare(text, best[:bestLen]) < 0 {
			bestLen = copy(best[:], text)
			report.NetworkRecords = n
		}
	}
	report.Network = string(best[:bestLen])
	report.Dropped = db.mailEvictPending
	db.mailEvictPending, db.mailEvictReport = 0, at
	return &report
}
