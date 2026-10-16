package attackdb

import (
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/spamscore"
	"github.com/pidginhost/csm/internal/store"
)

// MailEvidence is the attack DB record's mail section (feeds spec 7.3).
type MailEvidence = store.MailEvidence

const (
	// SpamListScore is the spam score at which the CSM IP map lists a
	// sender: two recent spam verdicts with no ham.
	SpamListScore = 50
	// mailAuthWindow is how long a mail login attack lists its source.
	mailAuthWindow = 30 * 24 * time.Hour
)

// mailAuthChecks name one source address attacking mail logins. The spray
// findings name networks, not an address, so RecordFinding never sees them.
var mailAuthChecks = map[string]bool{
	"smtp_bruteforce": true, "smtp_probe_abuse": true,
	"mail_bruteforce": true, "mail_account_compromised": true,
}

func (r *IPRecord) mail() *MailEvidence {
	if r.Mail == nil {
		r.Mail = &MailEvidence{}
	}
	return r.Mail
}

// recordMailAuthLocked counts a mail login attack in rec's mail section.
// Existing scoring is unchanged; the caller holds db.mu.
func recordMailAuthLocked(rec *IPRecord, check string, at time.Time) {
	if !mailAuthChecks[config.CanonicalCheckName(check)] {
		return
	}
	m := rec.mail()
	m.AuthAttacks++
	if at.After(m.LastAuthAttack) {
		m.LastAuthAttack = at
	}
}

// decayTo brings m's masses forward to at.
func decayTo(m *MailEvidence, at time.Time) {
	if !m.MassAt.IsZero() && at.After(m.MassAt) {
		f := spamscore.Recency(at.Sub(m.MassAt))
		m.SpamMass *= f
		m.HamMass *= f
	}
	if at.After(m.MassAt) {
		m.MassAt = at
	}
}

// RecordMailVerdict adds one scan verdict for ip. Spam creates the record;
// ham only updates a record that exists, so large legitimate senders never
// fill the attack DB. Neither touches EventCount, AttackCounts or
// ThreatScore, and no event is queued (feeds spec 7.3).
func (db *DB) RecordMailVerdict(ip string, spam bool, at time.Time) {
	db.mu.Lock()
	defer db.mu.Unlock()
	rec, ok := db.records[ip]
	if !ok {
		if !spam {
			return
		}
		rec = &IPRecord{IP: ip, FirstSeen: at, AttackCounts: make(map[AttackType]int), Accounts: make(map[string]int)}
		db.records[ip] = rec
	}
	m := rec.mail()
	decayTo(m, at)
	if spam {
		m.Spam++
		m.SpamMass++
		if at.After(m.LastSpam) {
			m.LastSpam = at
		}
		// Spam is activity: it keeps the 90-day prune correct. Ham is not.
		if at.After(rec.LastSeen) {
			rec.LastSeen = at
		}
	} else {
		m.Ham++
		m.HamMass++
	}
	delete(db.deletedIPs, ip)
	db.markDirtyLocked(ip)
}

// SpamScore is m's spam score at now, 0 to 100 (feeds spec 7.4).
func SpamScore(m *MailEvidence, now time.Time) int {
	if m == nil {
		return 0
	}
	f := 1.0
	if !m.MassAt.IsZero() && now.After(m.MassAt) {
		f = spamscore.Recency(now.Sub(m.MassAt))
	}
	spam, ham := m.SpamMass*f, m.HamMass*f
	return spamscore.Score(spam, spam+ham)
}

// MapSources lists the addresses the CSM IP map takes from the attack DB,
// sorted: mail login attacks in the last 30 days, and spam scores of
// SpamListScore or more.
func (db *DB) MapSources(now time.Time) (auth, spam []string) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	for ip, rec := range db.records {
		m := rec.Mail
		if m == nil {
			continue
		}
		if m.AuthAttacks > 0 && now.Sub(m.LastAuthAttack) <= mailAuthWindow {
			auth = append(auth, ip)
		}
		if SpamScore(m, now) >= SpamListScore {
			spam = append(spam, ip)
		}
	}
	slices.Sort(auth)
	slices.Sort(spam)
	return auth, spam
}

// TopSpamSenders returns copies of up to n records with spam verdicts,
// highest spam score first, then most spam, then address.
func (db *DB) TopSpamSenders(n int, now time.Time) []*IPRecord {
	db.mu.RLock()
	var out []*IPRecord
	for _, rec := range db.records {
		if rec.Mail != nil && rec.Mail.Spam > 0 {
			out = append(out, cloneIPRecord(rec))
		}
	}
	db.mu.RUnlock()
	slices.SortFunc(out, func(a, b *IPRecord) int {
		if d := SpamScore(b.Mail, now) - SpamScore(a.Mail, now); d != 0 {
			return d
		}
		if d := b.Mail.Spam - a.Mail.Spam; d != 0 {
			return d
		}
		return strings.Compare(a.IP, b.IP)
	})
	return out[:min(n, len(out))]
}
