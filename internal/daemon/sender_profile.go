package daemon

import (
	"fmt"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/eximlog"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/store"
)

// --- Authenticated sender profile ---------------------------------------
//
// A stolen mailbox password is used politely: well under any global rate
// limit, from residential addresses with no cloud PTR, with each message to
// a different victim. What gives it away is the mailbox's own history. The
// owner sends from one or two addresses a day in one country to a stable set
// of correspondents; the thief rotates addresses per message, appears from a
// country the mailbox never sent from, or mails more distinct recipients in a
// day than the owner does in a month. Credential checkers that validate a
// stolen password send one probe each from several countries within minutes.
//
// Each authenticated arrival updates a rolling one-hour window in memory and
// the mailbox's per-day record in the store. Thresholds are the larger of a
// floor and twice the mailbox's own prior maximum, so a busy shared mailbox
// earns a higher bar than a one-person box. Address blocking is deliberately
// not used: the sources rotate and may include the owner's own address, so a
// Critical finding suspends the mailbox instead.

const (
	senderHourWindow       = time.Hour
	senderMinCountriesHour = 3  // distinct source countries in one hour; no traveller reaches it
	senderIPFloorHour      = 4  // distinct source addresses in one hour
	senderIPFloorDay       = 6  // distinct source addresses in one UTC day
	senderRcptFloorDay     = 50 // distinct recipients in one UTC day, each in its own message
	senderBaselineDays     = 14 // prior days that form the mailbox's own maxima
	senderBaselineMinDays  = 3  // prior active days before an unseen country counts as new
	senderDedupCooldown    = time.Hour
	senderMaxHourEvents    = 1024
	senderMaxDaySet        = 512 // per-day cap on distinct addresses and recipients kept
)

type senderEvent struct {
	at      time.Time
	ip      string
	country string
}

type senderWindow struct {
	mu            sync.Mutex
	events        []senderEvent
	firedAt       time.Time
	firedSeverity alert.Severity
	lastEvent     time.Time
}

// senderWindows holds the rolling hour per authenticated mailbox.
var senderWindows sync.Map // map[string]*senderWindow

func lockSenderWindow(user string, now time.Time) *senderWindow {
	for {
		val, _ := senderWindows.LoadOrStore(user, &senderWindow{lastEvent: now})
		w := val.(*senderWindow)
		w.mu.Lock()
		// Re-check under the lock so an eviction sweep cannot delete the
		// entry between the load and the update.
		if current, ok := senderWindows.Load(user); ok && current == val {
			return w
		}
		w.mu.Unlock()
	}
}

type senderBaselineStats struct {
	activeDays    int
	maxHourIPs    int
	maxDayIPs     int
	maxRecipients int
	countries     map[string]bool
}

// senderBaseline summarises the prior days inside the baseline window.
func senderBaseline(p store.SenderProfile, now time.Time) senderBaselineStats {
	b := senderBaselineStats{countries: map[string]bool{}}
	today := senderDayKey(now)
	oldest := senderDayKey(now.AddDate(0, 0, -senderBaselineDays))
	for key, d := range p.Days {
		if d == nil || key == today || key < oldest {
			continue
		}
		b.activeDays++
		b.maxHourIPs = max(b.maxHourIPs, d.MaxHourIPs)
		b.maxDayIPs = max(b.maxDayIPs, len(d.IPs))
		b.maxRecipients = max(b.maxRecipients, len(d.Recipients))
		for _, c := range d.Countries {
			b.countries[c] = true
		}
	}
	return b
}

func senderDayKey(t time.Time) string { return t.UTC().Format("2006-01-02") }

// senderThreshold is the floor or twice the mailbox's own maximum plus one,
// whichever is higher.
func senderThreshold(floor, own int) int {
	return max(floor, 2*own+1)
}

func addDistinct(set []string, v string, limit int) []string {
	if slices.Contains(set, v) || len(set) >= limit {
		return set
	}
	return append(set, v)
}

func countryTrusted(country string, trusted []string) bool {
	for _, tc := range trusted {
		if strings.EqualFold(country, tc) {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

func recentSenderIPs(events []senderEvent, n int) []string {
	var ips []string
	for i := len(events) - 1; i >= 0 && len(ips) < n; i-- {
		ips = addDistinct(ips, events[i].ip, n)
	}
	return ips
}

// parseSenderProfileFinding evaluates one authenticated Exim arrival against
// the sender's own history. It returns at most one email_compromised_account
// finding and never acts on its own; the caller responds to Critical ones.
func parseSenderProfileFinding(line string, cfg *config.Config, now time.Time) (findings []alert.Finding) {
	if !strings.Contains(line, " <= ") || !strings.Contains(line, "A=dovecot_") {
		return nil
	}
	user := extractAuthUser(line)
	if user == "" || isHighVolumeSender(user, cfg.EmailProtection.HighVolumeSenders) {
		return nil
	}
	ip := eximlog.ClientIP(line)
	if ip == "" {
		return nil
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}
	country := ""
	if !isPrivateOrLoopback(ip) && !isInfraIPDaemon(ip, cfg.InfraIPs) {
		country = geoLookup(ip).Country
	}
	recipients := eximlog.Recipients(line)
	db := store.Global()

	// Registered before the unlock defer so owner I/O runs after it.
	defer func() { stampMailAccountOwner(findings, user) }()
	w := lockSenderWindow(user, now)
	defer w.mu.Unlock()

	cutoff := now.Add(-senderHourWindow)
	kept := w.events[:0]
	for _, e := range w.events {
		if e.at.After(cutoff) {
			kept = append(kept, e)
		}
	}
	w.events = kept
	if len(w.events) < senderMaxHourEvents {
		w.events = append(w.events, senderEvent{at: now, ip: ip, country: country})
	}
	w.lastEvent = now
	hourIPs := map[string]struct{}{}
	hourCountries := map[string]struct{}{}
	for _, e := range w.events {
		hourIPs[e.ip] = struct{}{}
		if e.country != "" {
			hourCountries[e.country] = struct{}{}
		}
	}

	var profile store.SenderProfile
	if db != nil {
		profile, _ = db.GetSenderProfile(user)
	}
	if profile.Days == nil {
		profile.Days = map[string]*store.SenderDay{}
	}
	today := senderDayKey(now)
	day := profile.Days[today]
	if day == nil {
		day = &store.SenderDay{}
		profile.Days[today] = day
	}
	day.Sends++
	day.IPs = addDistinct(day.IPs, ip, senderMaxDaySet)
	if country != "" {
		day.Countries = addDistinct(day.Countries, country, senderMaxDaySet)
	}
	for _, r := range recipients {
		day.Recipients = addDistinct(day.Recipients, strings.ToLower(r), senderMaxDaySet)
	}
	day.MaxHourIPs = max(day.MaxHourIPs, len(hourIPs))
	base := senderBaseline(profile, now)
	if db != nil {
		oldest := senderDayKey(now.AddDate(0, 0, -senderBaselineDays))
		for key := range profile.Days {
			if key < oldest {
				delete(profile.Days, key)
			}
		}
		if err := db.SetSenderProfile(user, profile); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] Warning: failed to save sender profile for %s: %v\n",
				now.Format("2006-01-02 15:04:05"), user, err)
		}
	}

	var reasons []string
	if len(hourCountries) >= senderMinCountriesHour {
		reasons = append(reasons, fmt.Sprintf("sent from %d countries within an hour (%s)",
			len(hourCountries), strings.Join(sortedKeys(hourCountries), ", ")))
	}
	critical := len(reasons) > 0
	var churn []string
	if len(hourIPs) >= senderThreshold(senderIPFloorHour, base.maxHourIPs) {
		churn = append(churn, fmt.Sprintf("sent from %d addresses within an hour (own history: at most %d)",
			len(hourIPs), base.maxHourIPs))
	}
	if len(day.IPs) >= senderThreshold(senderIPFloorDay, base.maxDayIPs) {
		churn = append(churn, fmt.Sprintf("sent from %d addresses today (own history: at most %d a day)",
			len(day.IPs), base.maxDayIPs))
	}
	if rcptThreshold := senderThreshold(senderRcptFloorDay, base.maxRecipients); len(day.Recipients) >= rcptThreshold && day.Sends >= rcptThreshold {
		churn = append(churn, fmt.Sprintf("mailed %d recipients today in %d messages (own history: at most %d a day)",
			len(day.Recipients), day.Sends, base.maxRecipients))
	}
	if len(churn) == 0 && !critical {
		return nil
	}
	reasons = append(reasons, churn...)
	if len(churn) > 0 && country != "" && base.activeDays >= senderBaselineMinDays &&
		!base.countries[country] && !countryTrusted(country, cfg.Suppressions.TrustedCountries) {
		reasons = append(reasons, fmt.Sprintf("country %s never seen for this mailbox in %d active days (known: %s)",
			country, base.activeDays, strings.Join(sortedKeys(base.countries), ", ")))
		critical = true
	}
	severity := alert.High
	if critical {
		severity = alert.Critical
	}

	// One finding per severity per cooldown; an escalation passes.
	if !w.firedAt.IsZero() && now.Sub(w.firedAt) < senderDedupCooldown && severity <= w.firedSeverity {
		return nil
	}
	w.firedAt, w.firedSeverity = now, severity

	message := fmt.Sprintf("Email account %s: %s", user, strings.Join(reasons, "; "))
	if critical {
		message += " - credentials compromised"
	}
	details := fmt.Sprintf(
		"Authenticated SMTP submissions for %s:\n"+
			"  last hour: %d messages, %d source addresses, %d countries\n"+
			"  today (UTC): %d messages, %d source addresses, %d recipients\n"+
			"  own history (%d active days of %d): at most %d addresses an hour, %d a day, %d recipients a day\n"+
			"  recent addresses: %s\n\n"+
			"The mailbox's own history sets the bar, so a shared or travelling mailbox is judged "+
			"against its habit rather than a global number. Source addresses are not blocked because "+
			"they rotate and may include the owner's own; a Critical finding suspends the mailbox's "+
			"logins and outgoing mail under the auto-response settings.",
		user, len(w.events), len(hourIPs), len(hourCountries),
		day.Sends, len(day.IPs), len(day.Recipients),
		base.activeDays, senderBaselineDays, base.maxHourIPs, base.maxDayIPs, base.maxRecipients,
		strings.Join(recentSenderIPs(w.events, 8), ", "))

	mailbox, domain, _ := splitMailAccount(user)
	return []alert.Finding{{
		Severity:  severity,
		Check:     "email_compromised_account",
		Message:   message,
		Details:   truncateDaemon(details, 900),
		Mailbox:   mailbox,
		Domain:    domain,
		Timestamp: now,
	}}
}

// respondToMailboxCompromise suspends the abused credential and marks its
// domain so rate alerts stay quiet while the response settles. The domain
// marker is correlation state, not an auto-response action, so it is kept
// even when the suspension is disabled or dry-run gated.
func respondToMailboxCompromise(cfg *config.Config, authUser, reason string) {
	if domain := extractDomainFromEmail(authUser); domain != "" {
		maybeSuspendMailbox(cfg, authUser, reason)
		RecordCompromisedDomain(domain)
	}
}

// senderEvictWindow is how long a per-user window may stay idle before it is
// evicted: twice the rolling hour, so the dedup guard outlives the window.
const senderEvictWindow = 2 * senderHourWindow

// StartSenderProfileEviction prunes idle per-user windows so the map does not
// grow with every authenticated sender ever seen.
func StartSenderProfileEviction(stopCh <-chan struct{}) {
	obs.Go("sender-profile-eviction", func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case now := <-ticker.C:
				evictSenderWindows(now)
			}
		}
	})
}

func evictSenderWindows(now time.Time) {
	cutoff := now.Add(-senderEvictWindow)
	senderWindows.Range(func(key, val any) bool {
		w := val.(*senderWindow)
		w.mu.Lock()
		if w.lastEvent.Before(cutoff) {
			senderWindows.CompareAndDelete(key, val)
		}
		w.mu.Unlock()
		return true
	})
}
