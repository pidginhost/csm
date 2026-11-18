package daemon

import (
	"fmt"
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
	if old := m.ring[m.next]; old != "" {
		delete(m.byID, old)
	}
	m.ring[m.next] = id
	m.next = (m.next + 1) % authSendsMax
	m.byID[id] = login
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
	events   []reputationEvent
	reported string // UTC day of the last report
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

// add records one deferral and returns the hour's count and its top sender
// when the address crosses the threshold for the first time today.
func (r *reputationTracker) add(ip, login string, now time.Time) (count int, top string, topCount int, fire bool) {
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
				if len(old.events) == 0 || old.events[len(old.events)-1].at.Before(cutoff) {
					delete(r.byIP, key)
				}
			}
			if len(r.byIP) >= reputationAddressesMax {
				return 0, "", 0, false
			}
		}
		a = &reputationAddress{}
		r.byIP[ip] = a
	}
	a.events = slices.DeleteFunc(a.events, func(e reputationEvent) bool { return e.at.Before(cutoff) })
	if len(a.events) == reputationEventsMax {
		a.events = a.events[1:]
	}
	a.events = append(a.events, reputationEvent{at: now, login: login})
	day := now.UTC().Format("2006-01-02")
	if len(a.events) < reputationDeferralsPerHour || a.reported == day {
		return len(a.events), "", 0, false
	}
	a.reported = day
	counts := map[string]int{}
	for _, e := range a.events {
		if e.login != "" {
			counts[e.login]++
		}
	}
	for _, login := range sortedKeys(counts) {
		if counts[login] > topCount {
			top, topCount = login, counts[login]
		}
	}
	return len(a.events), top, topCount, true
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
	login, _ := authSends.sender(d.MessageID)
	count, top, topCount, fire := reputationWindows.add(d.OutboundIP, login, now)
	if !fire || !persistReputationReport(d.OutboundIP, now) {
		return nil
	}
	message := fmt.Sprintf("Outbound address %s: %d reputation deferrals or refusals within an hour", d.OutboundIP, count)
	if top != "" {
		message += fmt.Sprintf("; top authenticated sender %s (%d)", top, topCount)
	}
	summary := []alert.Finding{{
		Severity:  alert.Warning,
		Check:     "email_outbound_reputation",
		Message:   message,
		Details:   "Last refusal: " + d.Text,
		Timestamp: now,
	}}
	if top == "" {
		return summary
	}
	summary[0].Mailbox, summary[0].Domain, _ = splitMailAccount(top)
	stampMailAccountOwner(summary, top)
	// The address is reported daily even while its evidence is still held.
	return append(summary, observeMailboxSignal(cfg, top, mailboxSignal{
		kind: signalReputation, key: d.OutboundIP, at: now,
		detail: fmt.Sprintf("sent %d of %d mails refused for the reputation of %s within an hour", topCount, count, d.OutboundIP),
	})...)
}

// persistReputationReport claims today's report for an address, so a
// restart does not report it again.
func persistReputationReport(ip string, now time.Time) bool {
	db := store.Global()
	if db == nil {
		return true
	}
	key := "email:reputation_report:" + ip
	day := now.UTC().Format("2006-01-02")
	if db.GetMetaString(key) == day {
		return false
	}
	_ = db.SetMetaString(key, day)
	return true
}
