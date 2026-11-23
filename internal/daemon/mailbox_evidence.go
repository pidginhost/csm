package daemon

import (
	"crypto/sha256"
	"fmt"
	"net/mail"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// --- Mailbox compromise evidence ----------------------------------------
//
// A stolen mailbox shows itself through several weak signs, each of which
// an honest owner also produces now and then: a login from abroad, a large
// mailing, a forward to a private address. Reporting each one separately
// floods a busy server's operators. Instead each sign is evidence in the
// mailbox's ledger, reported only in the daily summary, and the mailbox is
// suspended, with one urgent finding, once the evidence adds up.

const (
	signalNewCountry     = "new_country"
	signalForgedSender   = "forged_sender"
	signalBulkRecipients = "bulk_recipients"
	signalRedirect       = "redirect"
	signalReputation     = "reputation"
	// A login after failed logins: an owner mistyping a password twice
	// looks the same, so it needs another sign to suspend.
	signalCrack = "crack"
	// A login after at least the brute-force threshold of failures is
	// guessing, not a typo: it suspends on its own.
	signalBruteCrack = "brute_crack"
)

const (
	// Two independent signs. No single sign reaches it.
	mailboxCompromiseScore = 4
	// Evidence older than a week no longer describes the current session.
	mailboxEvidenceTTL = 7 * 24 * time.Hour
	// A thief plants a redirect soon after the login that stole the box.
	redirectAfterLoginWindow = 30 * 24 * time.Hour
	// A traveller crosses one border a day; two new countries in a day
	// is a shared password.
	newCountryPairWindow = 24 * time.Hour
	// Keys come from attacker-chosen values such as a forged sender
	// domain; rotating them must not grow the ledger.
	mailboxSignalKeysPerKind = 16
)

// mailboxSignal is one sign of compromise. since, when set, is when the
// evidence began, earlier than its observation: a redirect's file time.
// summary, when set, is the summary-class finding that reports the sign
// the first time the ledger holds it.
type mailboxSignal struct {
	kind    string
	key     string
	at      time.Time
	since   time.Time
	detail  string
	summary alert.Finding
}

// mailboxEvidenceScore weighs each kind of sign once, whatever its repeats.
func mailboxEvidenceScore(e store.MailboxEvidence) int {
	score := 0
	seen := make(map[string]bool)
	var countryPair, datedRedirect bool
	for i, s := range e.Signals {
		switch s.Kind {
		case signalNewCountry:
			if !s.Overflow && !countryPair {
				countryPair = slices.ContainsFunc(e.Signals[:i], func(other store.MailboxSignal) bool {
					return other.Kind == s.Kind && !other.Overflow && other.Key != s.Key && nearbyCountrySightings(s, other)
				})
			}
		case signalRedirect:
			datedRedirect = datedRedirect || !s.LastDatedRedirect.IsZero() || !s.Overflow && followsForeignLogin(s.First, e.LastNewCountry)
		}
		if seen[s.Kind] {
			continue
		}
		seen[s.Kind] = true
		switch s.Kind {
		case signalNewCountry, signalRedirect, signalBulkRecipients, signalCrack:
			score += 2
		case signalBruteCrack:
			score += mailboxCompromiseScore
		case signalForgedSender:
			score += 3
		case signalReputation:
			score++
		}
	}
	if countryPair {
		score += 2
	}
	if datedRedirect {
		score++
	}
	return score
}

// Country sightings are grouped by UTC day. Across adjacent days the
// nearest actual sightings are the last on one day and the first on the other.
func nearbyCountrySightings(a, b store.MailboxSignal) bool {
	return a.First.Sub(b.First).Abs() <= newCountryPairWindow ||
		a.Last.Sub(b.First).Abs() <= newCountryPairWindow ||
		a.First.Sub(b.Last).Abs() <= newCountryPairWindow ||
		a.Last.Sub(b.Last).Abs() <= newCountryPairWindow
}

func followsForeignLogin(created, login time.Time) bool {
	return !login.IsZero() && !created.Before(login) && created.Sub(login) <= redirectAfterLoginWindow
}

// expireMailboxEvidence drops evidence past its TTL. An incident whose
// evidence no longer adds up is over, so the next one reports again.
func expireMailboxEvidence(e *store.MailboxEvidence, now time.Time) {
	cutoff := now.Add(-mailboxEvidenceTTL)
	e.Signals = slices.DeleteFunc(e.Signals, func(s store.MailboxSignal) bool { return s.Last.Before(cutoff) })
	// An overflow row can outlive the qualifying redirect it includes.
	for i := range e.Signals {
		if e.Signals[i].LastDatedRedirect.Before(cutoff) {
			e.Signals[i].LastDatedRedirect = time.Time{}
		}
	}
	if e.ClearedAt.Before(cutoff) {
		e.ClearedAt = time.Time{}
	}
	if e.LastNewCountry.Before(now.Add(-redirectAfterLoginWindow)) {
		e.LastNewCountry = time.Time{}
	}
	if e.ReportedAt != nil && mailboxEvidenceScore(*e) < mailboxCompromiseScore {
		e.ReportedAt = nil
	}
}

// pruneMailboxEvidence expires every ledger, including those of mailboxes
// that never show another sign.
func pruneMailboxEvidence(db *store.DB, now time.Time) error {
	return db.PruneMailboxEvidence(func(_ string, e *store.MailboxEvidence) { expireMailboxEvidence(e, now) })
}

// observeMailboxSignal adds a sign to the mailbox's ledger and returns its
// summary finding when the sign is new to the ledger. The first time the
// ledger reaches the compromise score it also suspends the mailbox and
// returns the one incident finding.
func observeMailboxSignal(cfg *config.Config, mailbox string, s mailboxSignal) (out []alert.Finding) {
	mailbox = store.MailboxEvidenceKey(mailbox)
	if len(mailbox) > maxSprayMailboxBytes || !strings.Contains(mailbox, "@") {
		return nil
	}
	if _, err := mail.ParseAddress("<" + mailbox + ">"); err != nil {
		return nil
	}
	switch s.kind {
	case signalForgedSender, signalBulkRecipients:
		if cfg != nil && isHighVolumeSender(mailbox, cfg.EmailProtection.HighVolumeSenders) {
			return nil
		}
	case signalNewCountry, signalRedirect, signalReputation, signalCrack, signalBruteCrack:
	default:
		return nil
	}
	db := store.Global()
	if db == nil {
		return nil
	}
	now := time.Now()
	if s.at.After(now) {
		s.at = now
	}
	if s.at.Before(now.Add(-mailboxEvidenceTTL)) {
		return nil
	}
	addressID := evidenceAddressLock(activeMailBackend.name(), mailbox)
	unlockAddress := lockMailResponse(addressID)
	fresh := false
	e, err := db.UpdateMailboxEvidence(mailbox, func(e *store.MailboxEvidence) {
		expireMailboxEvidence(e, now)
		if s.at.After(e.ClearedAt) {
			fresh = recordMailboxSignal(e, s)
			if s.kind == signalNewCountry || s.kind == signalRedirect {
				dateMailboxRedirects(e)
			}
		}
	})
	unlockAddress()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Warning: mailbox evidence for %s: %v\n", ts(), mailbox, err)
		return nil
	}
	if fresh && s.summary.Check != "" {
		out = append(out, s.summary)
	}
	if e.ReportedAt != nil || mailboxEvidenceScore(e) < mailboxCompromiseScore {
		return out
	}

	response := evidenceResponse{hasBackend: hostHasMailBackend(), id: addressID}
	if response.hasBackend && cfg != nil && cfg.AutoResponse.Enabled && !cfg.AutoResponseDryRunEnabled() && cfg.SuspendMailboxesEnabled() {
		response.id, response.ref, response.err = mailResponseTarget(mailbox)
		if response.err != nil {
			response.id = addressID
		}
	}
	// Release and reporting take these locks in the same order. Reading
	// again also discards claims overtaken by a concurrent report.
	unlock := lockMailResponse(response.id)
	defer unlock()
	if response.id != addressID {
		unlockAddress := lockMailResponse(addressID)
		defer unlockAddress()
	}
	e, err = response.currentEvidence(db, mailbox)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Warning: reading mailbox evidence for %s: %v\n", ts(), mailbox, err)
		return out
	}
	expireMailboxEvidence(&e, time.Now())
	score := mailboxEvidenceScore(e)
	if e.ReportedAt != nil || !s.at.After(e.ClearedAt) || score < mailboxCompromiseScore {
		return out
	}
	f := response.finding(cfg, db, mailbox, e, score)
	// A daemon restart between recording evidence and attempting the response
	// must leave the next observation able to finish the incident.
	if _, err := db.UpdateMailboxEvidence(mailbox, func(e *store.MailboxEvidence) { e.ReportedAt = &now }); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Warning: marking mailbox incident for %s: %v\n", ts(), mailbox, err)
	}
	return append(out, f)
}

// cPanel releases by address. Stalwart's account IDs have a separate
// namespace and can cover several addresses.
func evidenceAddressLock(backend, mailbox string) string {
	id := store.MailboxSuspensionID(backend, mailbox)
	if backend == "stalwart" {
		return "mailbox-address:" + id
	}
	return id
}

// recordMailboxSignal reports whether the sign is new to the ledger.
func recordMailboxSignal(e *store.MailboxEvidence, s mailboxSignal) bool {
	first := s.at
	if s.kind == signalRedirect && !s.since.IsZero() && s.since.Before(first) {
		first = s.since
	}
	if len(s.key) > 256 {
		s.key = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(s.key)))
	}
	if s.kind == signalNewCountry {
		e.LastNewCountry = maxTime(e.LastNewCountry, s.at)
	}
	keys, oldest, overflow := 0, -1, -1
	for i := range e.Signals {
		old := &e.Signals[i]
		if old.Kind != s.kind {
			continue
		}
		keys++
		if old.Overflow {
			overflow = i
			continue
		}
		sameDay := old.First.Truncate(24 * time.Hour).Equal(first.Truncate(24 * time.Hour))
		if old.Key == s.key && (s.kind != signalNewCountry || sameDay) {
			old.Count++
			old.Last = maxTime(old.Last, s.at)
			if first.Before(old.First) {
				old.First = first
				old.LastDatedRedirect = time.Time{}
			}
			return false
		}
		if oldest < 0 || old.Last.Before(e.Signals[oldest].Last) {
			oldest = i
		}
	}
	next := store.MailboxSignal{Kind: s.kind, Key: s.key, First: first, Last: s.at, Count: 1, Detail: truncateDaemon(s.detail, 300)}
	if keys < mailboxSignalKeysPerKind {
		e.Signals = append(e.Signals, next)
		return true
	}
	// Keep a count for displaced keys without attributing their sightings
	// to any of the individual keys still named in the incident.
	if overflow < 0 {
		old := &e.Signals[oldest]
		old.Key, old.Detail, old.Overflow = "", "Additional "+s.kind+" observations", true
		return recordMailboxSignal(e, s)
	}
	summary, displaced := &e.Signals[overflow], e.Signals[oldest]
	summary.Count += displaced.Count
	summary.LastDatedRedirect = maxTime(summary.LastDatedRedirect, displaced.LastDatedRedirect)
	if displaced.First.Before(summary.First) {
		summary.First = displaced.First
	}
	summary.Last = maxTime(summary.Last, displaced.Last)
	e.Signals[oldest] = next
	// Past the cap a rotated key is not reported again either.
	return false
}

// Preserve a confirmed creation time relationship after its login ages
// out or a newer login becomes the mailbox's most recent one.
func dateMailboxRedirects(e *store.MailboxEvidence) {
	for i := range e.Signals {
		redirect := &e.Signals[i]
		if redirect.Kind != signalRedirect || redirect.Overflow {
			continue
		}
		if !redirect.LastDatedRedirect.IsZero() || followsForeignLogin(redirect.First, e.LastNewCountry) ||
			slices.ContainsFunc(e.Signals, func(s store.MailboxSignal) bool {
				return s.Kind == signalNewCountry && !s.Overflow &&
					(followsForeignLogin(redirect.First, s.First) || followsForeignLogin(redirect.First, s.Last))
			}) {
			redirect.LastDatedRedirect = redirect.Last
		}
	}
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

type evidenceResponse struct {
	id, ref    string
	err        error
	hasBackend bool
}

// Older releases have a suspension record but no cutoff in the ledger.
func (r evidenceResponse) currentEvidence(db *store.DB, mailbox string) (store.MailboxEvidence, error) {
	e, err := db.GetMailboxEvidence(mailbox)
	if err != nil || len(e.Signals) == 0 {
		return e, err
	}
	var released time.Time
	if activeMailBackend.name() == "stalwart" && r.ref == "" {
		// Observational mode must not contact the directory to get an ID.
		rows, err := db.ListMailboxSuspensions()
		if err != nil {
			return e, err
		}
		for _, row := range rows {
			if row.Backend == "stalwart" && store.MailboxEvidenceKey(row.Subject) == mailbox && row.ReleasedAt != nil {
				released = maxTime(released, *row.ReleasedAt)
			}
		}
	} else {
		row, _, err := db.GetMailboxSuspension(r.id)
		if err != nil {
			return e, err
		}
		if row.ReleasedAt != nil {
			released = *row.ReleasedAt
		}
	}
	if !released.After(e.ClearedAt) || released.Before(time.Now().Add(-mailboxEvidenceTTL)) {
		return e, nil
	}
	return db.UpdateMailboxEvidence(mailbox, func(e *store.MailboxEvidence) {
		e.ClearedAt = released
		e.Signals = slices.DeleteFunc(e.Signals, func(s store.MailboxSignal) bool { return !s.Last.After(released) })
		for i := range e.Signals {
			s := &e.Signals[i]
			if !s.First.After(released) {
				// Of a group spanning release, only its last observation is
				// known to belong to the new incident. Keep redirect creation time.
				if s.Kind != signalRedirect {
					s.First = s.Last
				}
				s.Count = 1
			}
			s.LastDatedRedirect = time.Time{}
		}
		if !e.LastNewCountry.After(released) {
			e.LastNewCountry = time.Time{}
		}
		if e.ReportedAt != nil && !e.ReportedAt.After(released) {
			e.ReportedAt = nil
		}
		dateMailboxRedirects(e)
	})
}

// finding suspends a mailbox whose evidence adds up and
// returns the incident finding: what was done, on what evidence, and how to
// undo it.
func (r evidenceResponse) finding(cfg *config.Config, db *store.DB, mailbox string, e store.MailboxEvidence, score int) alert.Finding {
	// Declaring the mailbox compromised withdraws its login standing in
	// every response mode, as respondToCompromise does.
	mailboxResponseStanding.Load().Revoke(mailbox)
	signals := slices.Clone(e.Signals)
	slices.SortFunc(signals, func(a, b store.MailboxSignal) int { return a.First.Compare(b.First) })
	var latest time.Time
	sending := false
	var kinds []string
	for _, s := range signals {
		latest = maxTime(latest, s.Last)
		if !slices.Contains(kinds, s.Kind) {
			kinds = append(kinds, s.Kind)
		}
		switch s.Kind {
		case signalForgedSender, signalBulkRecipients, signalReputation:
			sending = true
		}
	}
	reason := fmt.Sprintf("compromise evidence scored %d: %s", score, strings.Join(kinds, ", "))

	evidence := evidenceLogin
	if sending {
		evidence = evidenceSending
	}
	var applied store.MailboxSuspension
	c := mailboxCompromise{Subject: mailbox, Ref: r.ref, Check: "email_mailbox_compromise", Reason: reason, Evidence: evidence, At: latest}
	var verb, todo string
	switch {
	case !r.hasBackend:
		verb, todo = "Would suspend", "This mail server has no mailbox suspension. Change the mailbox password now."
	case cfg == nil || !cfg.AutoResponse.Enabled:
		verb, todo = "Would suspend", "Automatic response is off. Change the mailbox password now."
	case cfg.AutoResponseDryRunEnabled():
		recordMailDryRun(c)
		verb, todo = "Would suspend", "Automatic response is in dry-run. Change the mailbox password now."
	case !cfg.SuspendMailboxesEnabled():
		verb, todo = "Would suspend", "Mailbox suspension is off (auto_response.suspend_mailboxes). Change the mailbox password now."
	default:
		result := mailResponseResult{err: r.err}
		if r.err == nil {
			result = applyMailResponse(db, r.id, c)
		}
		applied = result.record
		switch {
		case result.withheld != "":
			verb = "Would suspend"
			todo = fmt.Sprintf("Mailbox suspension is paused for %s after %d suspensions in the last hour. Change the mailbox password now.", result.withheld, mailboxSuspensionsPerHour)
		case result.changed:
			verb = "Suspended"
			todo = mailRestrictionDetails(result.record) + " Have the customer change the mailbox password."
			if result.recorded {
				todo += " Release the restrictions on the Email page, Suspended tab."
			} else {
				todo += " CSM could not save the suspension. Check the action log and release the restrictions on the mail server."
			}
		case result.stopped:
			verb, todo = "Already restricted", "The mailbox or its account is already restricted. Review the existing restrictions and change the mailbox password."
		default:
			verb, todo = "Could not suspend", "Protection could not be confirmed. Change the mailbox password now."
			if result.err != nil {
				todo += " " + result.err.Error()
			}
		}
	}
	RecordCompromisedDomain(extractDomainFromEmail(mailbox))

	var details strings.Builder
	details.WriteString("Evidence:\n")
	for _, s := range signals {
		fmt.Fprintf(&details, "  %s  %s", s.First.UTC().Format("2006-01-02 15:04 UTC"), s.Detail)
		if s.Count > 1 {
			fmt.Fprintf(&details, " (%d times, last %s)", s.Count, s.Last.UTC().Format("2006-01-02 15:04 UTC"))
		}
		details.WriteString("\n")
	}
	details.WriteString("\n" + todo)
	if slices.ContainsFunc(signals, func(s store.MailboxSignal) bool { return s.Kind == signalRedirect }) {
		details.WriteString(" The redirect above is left in place as evidence; remove it after review.")
	}

	_, domain, tenant := splitMailAccount(mailbox)
	if applied.Account != "" {
		tenant = applied.Account
	} else if tenant == "" && domain != "" && activeMailBackend.name() != "stalwart" {
		tenant = lookupCPanelUser(domain)
	}
	f := []alert.Finding{{
		Severity:  alert.Critical,
		Check:     "email_mailbox_compromise",
		Message:   fmt.Sprintf("%s mailbox %s: compromise evidence scored %d", verb, mailbox, score),
		Details:   details.String(),
		Mailbox:   mailbox,
		Domain:    domain,
		Timestamp: time.Now(),
	}}
	stampMailAccountOwner(f, mailbox)
	// The response resolved its own owner; a separate cache must not
	// replace that account or erase it while retaining the mailbox claim.
	if tenant != "" {
		f[0].TenantID = tenant
	}
	return f[0]
}
