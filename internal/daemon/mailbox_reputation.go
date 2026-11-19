package daemon

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mailfwd/intel"
	"github.com/pidginhost/csm/internal/store"
)

const (
	// Reputation deferrals naming one of this server's addresses within an
	// hour: a provider refusing the address, not one unlucky message.
	reputationDeferralsPerHour = 20
	// Providers retry a deferred message for days; remember who sent it.
	authSendsMax = 1 << 16
	// The address is read from remote error text, so a hostile server can
	// name any address. Bound what it can make CSM keep.
	reputationAddressesMax = 256
	reputationEventsMax    = 4096
)

// authSendMap remembers the login behind recent authenticated arrivals, so
// a deferral days later can name the mailbox that sent the message.
type authSendMap struct {
	mu   sync.Mutex
	byID map[string]string
	ring []string
	next int
}

var authSends = &authSendMap{}

func (m *authSendMap) note(id, login string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byID == nil {
		m.byID = make(map[string]string)
		m.ring = make([]string, authSendsMax)
	}
	// A replay of the arrival must not leave two eviction slots for one ID.
	if _, present := m.byID[id]; present {
		return
	}
	if old := m.ring[m.next]; old != "" {
		delete(m.byID, old)
	}
	// The parsed ID can share storage with the entire Exim log line.
	id = strings.Clone(id)
	m.ring[m.next] = id
	m.next = (m.next + 1) % authSendsMax
	m.byID[id] = strings.Clone(login)
}

func (m *authSendMap) sender(id string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	login, ok := m.byID[id]
	return login, ok
}

func (m *authSendMap) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byID)
}

func (m *authSendMap) reset() {
	m.mu.Lock()
	m.byID, m.ring, m.next = nil, nil, 0
	m.mu.Unlock()
}

type reputationEvent struct {
	at    time.Time
	login string
}

type reputationAddress struct {
	displaced time.Time // latest refusal omitted at the event cap
	credited  time.Time
	latest    time.Time
	events    []reputationEvent
	reported  string // UTC day of the last report
}

// reputationTracker keeps the last hour of reputation deferrals per
// outbound address.
type reputationTracker struct {
	mu   sync.Mutex
	byIP map[string]*reputationAddress
}

var reputationWindows = &reputationTracker{}

func (r *reputationTracker) reset() {
	r.mu.Lock()
	r.byIP = nil
	r.mu.Unlock()
}

type reputationReport struct {
	count, topCount   int
	top               string
	lastRefusal       time.Time
	summary, evidence bool
	incomplete        bool
}

func (r *reputationTracker) add(ip, login string, at, now time.Time) reputationReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byIP == nil {
		r.byIP = make(map[string]*reputationAddress)
	}
	cutoff := now.Add(-time.Hour)
	a := r.byIP[ip]
	if a == nil {
		if len(r.byIP) >= reputationAddressesMax {
			for key, old := range r.byIP {
				if len(old.events) == 0 || old.latest.Before(cutoff) {
					delete(r.byIP, key)
				}
			}
			if len(r.byIP) >= reputationAddressesMax {
				return reputationReport{}
			}
		}
		a = &reputationAddress{}
		r.byIP[ip] = a
	}
	a.latest = maxTime(a.latest, at)
	a.events = slices.DeleteFunc(a.events, func(e reputationEvent) bool { return e.at.Before(cutoff) })
	if len(a.events) == reputationEventsMax {
		a.displaced = maxTime(a.displaced, a.events[0].at)
		a.events = a.events[1:]
	}
	a.events = append(a.events, reputationEvent{at: at, login: login})
	day := now.UTC().Format(time.DateOnly)
	report := reputationReport{count: len(a.events)}
	due := !a.credited.After(cutoff)
	if report.count < reputationDeferralsPerHour || (a.reported == day && (!due || login == "")) {
		return report
	}
	if a.reported != day {
		report.summary = true
		if db := store.Global(); db != nil {
			claimed, err := db.ClaimReputationReport(ip, day)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] Warning: saving outbound reputation report: %v\n", ts(), err)
				return reputationReport{}
			}
			report.summary = claimed
		}
		a.reported = day
	}
	// While a displaced refusal belongs to this hour, the retained count
	// is a lower bound and the apparent top sender may be wrong.
	if !a.displaced.Before(cutoff) {
		report.incomplete = true
		return report
	}
	// A daily address notice and evidence for an hour's top sender have
	// independent lifetimes. A different mailbox can lead a later window.
	counts := map[string]int{}
	for _, e := range a.events {
		if e.login != "" {
			counts[e.login]++
		}
	}
	for login, n := range counts {
		switch {
		case n > report.topCount:
			report.top, report.topCount = login, n
		case n == report.topCount:
			report.top = ""
		}
	}
	if due && report.top != "" {
		for _, e := range a.events {
			if e.login == report.top {
				report.lastRefusal = maxTime(report.lastRefusal, e.at)
			}
		}
		a.credited, report.evidence = now, true
	}
	return report
}

// observeReputationOutcome reads a delivery deferral or failure. When
// providers refuse one of this server's addresses on reputation grounds,
// it reports the address once a day in the summary and adds evidence to the
// mailbox that sent most of the refused mail.
func observeReputationOutcome(cfg *config.Config, line string, now time.Time) []alert.Finding {
	if !strings.Contains(line, " == ") && !strings.Contains(line, " ** ") {
		return nil
	}
	d, ok := intel.ParseOutcome(line)
	if !ok || !d.Reputation || d.OutboundIP == "" {
		return nil
	}
	if d.Time.Before(now.Add(-time.Hour)) || d.Time.After(now) {
		return nil
	}
	login, _ := authSends.sender(d.MessageID)
	r := reputationWindows.add(d.OutboundIP, login, d.Time, now)
	var findings []alert.Finding
	if r.summary {
		count := fmt.Sprint(r.count)
		if r.incomplete {
			count = "at least " + count
		}
		message := fmt.Sprintf("Outbound address %s: %s reputation deferrals or refusals within an hour", d.OutboundIP, count)
		if r.top != "" {
			message += fmt.Sprintf("; top authenticated sender %s (%d)", r.top, r.topCount)
		}
		mailbox, domain, _ := splitMailAccount(r.top)
		findings = append(findings, alert.Finding{
			Severity:  alert.Warning,
			Check:     "email_outbound_reputation",
			Message:   message,
			Details:   "Last refusal: " + d.Text,
			Mailbox:   mailbox,
			Domain:    domain,
			Timestamp: now,
		})
		stampMailAccountOwner(findings, r.top)
	}
	if r.evidence {
		findings = append(findings, observeMailboxSignal(cfg, r.top, mailboxSignal{
			kind: signalReputation, key: d.OutboundIP, at: r.lastRefusal,
			detail: fmt.Sprintf("sent %d of %d mails refused for the reputation of %s within an hour", r.topCount, r.count, d.OutboundIP),
		})...)
	}
	return findings
}
