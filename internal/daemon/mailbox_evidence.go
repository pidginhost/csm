package daemon

import (
	"fmt"
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
	var countries []store.MailboxSignal
	for _, kind := range []string{signalNewCountry, signalForgedSender, signalBulkRecipients, signalRedirect, signalReputation} {
		var seen []store.MailboxSignal
		for _, s := range e.Signals {
			if s.Kind == kind {
				seen = append(seen, s)
			}
		}
		if len(seen) == 0 {
			continue
		}
		switch kind {
		case signalNewCountry:
			score += 2
			countries = seen
		case signalForgedSender:
			score += 3
		case signalBulkRecipients:
			score += 2
		case signalRedirect:
			score += 2
			if !e.LastNewCountry.IsZero() && slices.ContainsFunc(seen, func(s store.MailboxSignal) bool {
				return absDuration(s.First.Sub(e.LastNewCountry)) <= redirectAfterLoginWindow
			}) {
				score++
			}
		case signalReputation:
			score++
		}
	}
	for i := range countries {
		for j := i + 1; j < len(countries); j++ {
			if countries[i].Key != countries[j].Key && absDuration(countries[i].First.Sub(countries[j].First)) <= newCountryPairWindow {
				return score + 2
			}
		}
	}
	return score
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// expireMailboxEvidence drops evidence past its TTL. An incident whose
// evidence no longer adds up is over, so the next one reports again.
func expireMailboxEvidence(e *store.MailboxEvidence, now time.Time) {
	cutoff := now.Add(-mailboxEvidenceTTL)
	e.Signals = slices.DeleteFunc(e.Signals, func(s store.MailboxSignal) bool { return s.Last.Before(cutoff) })
	if e.ReportedAt != nil && mailboxEvidenceScore(*e) < mailboxCompromiseScore {
		e.ReportedAt = nil
	}
	if e.LastNewCountry.Before(now.Add(-redirectAfterLoginWindow)) {
		e.LastNewCountry = time.Time{}
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
func observeMailboxSignal(cfg *config.Config, mailbox string, s mailboxSignal) []alert.Finding {
	mailbox = strings.ToLower(mailbox)
	if !strings.Contains(mailbox, "@") {
		return nil
	}
	db := store.Global()
	if db == nil {
		return nil
	}
	first := s.at
	if !s.since.IsZero() && s.since.Before(first) {
		first = s.since
	}
	report, fresh := false, false
	score := 0
	// The claim on the report is made in the same transaction as the score,
	// so concurrent signs report one incident.
	e, err := db.UpdateMailboxEvidence(mailbox, func(e *store.MailboxEvidence) {
		now := time.Now()
		expireMailboxEvidence(e, now)
		if s.at.Before(now.Add(-mailboxEvidenceTTL)) {
			return
		}
		i := slices.IndexFunc(e.Signals, func(old store.MailboxSignal) bool { return old.Kind == s.kind && old.Key == s.key })
		if i < 0 && kindKeys(e.Signals, s.kind) >= mailboxSignalKeysPerKind {
			i = latestOfKind(e.Signals, s.kind)
		}
		if i < 0 {
			fresh = true
			e.Signals = append(e.Signals, store.MailboxSignal{Kind: s.kind, Key: s.key, First: first, Last: s.at, Count: 1, Detail: truncateDaemon(s.detail, 300)})
		} else {
			old := &e.Signals[i]
			old.Count++
			old.Last = maxTime(old.Last, s.at)
			if first.Before(old.First) {
				old.First = first
			}
		}
		if s.kind == signalNewCountry {
			e.LastNewCountry = maxTime(e.LastNewCountry, s.at)
		}
		score = mailboxEvidenceScore(*e)
		if score >= mailboxCompromiseScore && e.ReportedAt == nil {
			e.ReportedAt, report = &now, true
		}
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Warning: mailbox evidence for %s: %v\n", ts(), mailbox, err)
		return nil
	}
	var out []alert.Finding
	if fresh && s.summary.Check != "" {
		out = append(out, s.summary)
	}
	if report {
		out = append(out, respondToMailboxEvidence(cfg, mailbox, e, score))
	}
	return out
}

func kindKeys(signals []store.MailboxSignal, kind string) int {
	n := 0
	for _, s := range signals {
		if s.Kind == kind {
			n++
		}
	}
	return n
}

func latestOfKind(signals []store.MailboxSignal, kind string) int {
	i := -1
	for j, s := range signals {
		if s.Kind == kind && (i < 0 || s.Last.After(signals[i].Last)) {
			i = j
		}
	}
	return i
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// respondToMailboxEvidence suspends a mailbox whose evidence adds up and
// returns the incident finding: what was done, on what evidence, and how to
// undo it.
func respondToMailboxEvidence(cfg *config.Config, mailbox string, e store.MailboxEvidence, score int) alert.Finding {
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

	var verb, todo string
	switch {
	case !hostHasMailBackend():
		verb, todo = "Would suspend", "This mail server has no mailbox suspension. Change the mailbox password now."
	case cfg == nil || !cfg.AutoResponse.Enabled:
		verb, todo = "Would suspend", "Automatic response is off. Change the mailbox password now."
	case cfg.AutoResponseDryRunEnabled():
		verb, todo = "Would suspend", "Automatic response is in dry-run. Change the mailbox password now."
	default:
		evidence := evidenceLogin
		if sending {
			evidence = evidenceSending
		}
		// The incident finding below replaces the login response finding.
		stopped, _ := respondToCompromise(cfg, mailboxCompromise{
			Subject: mailbox, Check: "email_mailbox_compromise", Reason: reason, Evidence: evidence, At: latest,
		})
		if stopped {
			verb, todo = "Suspended", "Logins and outgoing mail are stopped. Have the customer change the mailbox password, then release it on the Email page, Suspended tab."
		} else {
			verb, todo = "Could not suspend", "Protection could not be confirmed. Change the mailbox password now."
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

	_, domain, _ := splitMailAccount(mailbox)
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
	return f[0]
}
