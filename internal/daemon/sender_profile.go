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
	senderFlushInterval    = time.Minute
	senderMaxDaySet        = 512 // per-day cap on distinct addresses and recipients kept
)

type senderEvent struct {
	at time.Time
	ip string
}

type senderWindow struct {
	mu            sync.Mutex
	events        []senderEvent
	firedAt       time.Time
	firedSeverity alert.Severity
	lastEvent     time.Time
	countries     map[string]time.Time
	profile       store.SenderProfile
	baseline      senderBaselineStats
	dayKey        string
	db            *store.DB
	loaded        bool
	dirty         bool
	loadAfter     time.Time
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
	oldest := senderDayKey(now.UTC().AddDate(0, 0, -senderBaselineDays))
	for key, d := range p.Days {
		if d == nil || key >= today || key < oldest {
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

	if !w.loaded || w.db != db {
		var profile store.SenderProfile
		if db != nil {
			if now.Before(w.loadAfter) {
				return nil
			}
			var err error
			profile, err = db.GetSenderProfile(user)
			if err != nil {
				w.loadAfter = now.Add(senderFlushInterval)
				fmt.Fprintf(os.Stderr, "[%s] Warning: failed to load sender profile for %s: %v\n",
					now.Format("2006-01-02 15:04:05"), user, err)
				return nil
			}
		}
		w.profile = profile
		w.db, w.loaded, w.dayKey = db, true, ""
	}
	if w.profile.Days == nil {
		w.profile.Days = map[string]*store.SenderDay{}
	}
	// Concurrent readers can capture their timestamps in the opposite order
	// to acquiring this lock. Never move the cache's day or idle time back.
	if now.Before(w.lastEvent) {
		now = w.lastEvent
	}
	w.lastEvent = now
	w.observeSource(now, ip, country)
	hourIPs := len(w.events)
	hourCountries := w.countries

	today := senderDayKey(now)
	if w.dayKey != today {
		oldest := senderDayKey(now.UTC().AddDate(0, 0, -senderBaselineDays))
		for key := range w.profile.Days {
			if key < oldest {
				delete(w.profile.Days, key)
			}
		}
		w.baseline = senderBaseline(w.profile, now)
		w.dayKey = today
	}
	day := w.profile.Days[today]
	if day == nil {
		day = &store.SenderDay{}
		w.profile.Days[today] = day
	}
	day.Sends++
	day.IPs = addDistinct(day.IPs, ip, senderMaxDaySet)
	if country != "" {
		day.Countries = addDistinct(day.Countries, country, senderMaxDaySet)
	}
	var messageRecipients []string
	for _, r := range recipients {
		r = strings.ToLower(r)
		day.Recipients = addDistinct(day.Recipients, r, senderMaxDaySet)
		// Only the distinction between one and multiple recipients matters.
		messageRecipients = addDistinct(messageRecipients, r, 2)
	}
	if len(messageRecipients) == 1 {
		day.SingleRecipients = addDistinct(day.SingleRecipients, messageRecipients[0], senderMaxDaySet)
	}
	day.MaxHourIPs = max(day.MaxHourIPs, hourIPs)
	w.dirty = true
	base := w.baseline

	var reasons []string
	if len(hourCountries) >= senderMinCountriesHour {
		reasons = append(reasons, fmt.Sprintf("sent from %d countries within an hour (%s)",
			len(hourCountries), strings.Join(sortedKeys(hourCountries), ", ")))
	}
	critical := len(reasons) > 0
	var churn []string
	if hourIPs >= senderThreshold(senderIPFloorHour, base.maxHourIPs) {
		churn = append(churn, fmt.Sprintf("sent from %d addresses within an hour (own history: at most %d)",
			hourIPs, base.maxHourIPs))
	}
	if len(day.IPs) >= senderThreshold(senderIPFloorDay, base.maxDayIPs) {
		churn = append(churn, fmt.Sprintf("sent from %d addresses today (own history: at most %d a day)",
			len(day.IPs), base.maxDayIPs))
	}
	if rcptThreshold := senderThreshold(senderRcptFloorDay, base.maxRecipients); len(day.SingleRecipients) >= rcptThreshold {
		churn = append(churn, fmt.Sprintf("mailed %d recipients individually today (own history: at most %d a day)",
			len(day.SingleRecipients), base.maxRecipients))
	}
	if len(churn) == 0 && !critical {
		return nil
	}
	reasons = append(reasons, churn...)
	if len(churn) > 0 && base.activeDays >= senderBaselineMinDays {
		for _, seenCountry := range day.Countries {
			if !base.countries[seenCountry] && !countryTrusted(seenCountry, cfg.Suppressions.TrustedCountries) {
				reasons = append(reasons, fmt.Sprintf("country %s never seen for this mailbox in %d active days (known: %s)",
					seenCountry, base.activeDays, strings.Join(sortedKeys(base.countries), ", ")))
				critical = true
				break
			}
		}
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
			"  last hour: %d source addresses, %d countries\n"+
			"  today (UTC): %d messages, %d source addresses, %d recipients\n"+
			"  own history (%d active days of %d): at most %d addresses an hour, %d a day, %d recipients a day\n"+
			"  recent addresses: %s\n\n"+
			"The mailbox's own history sets the bar, so a shared or travelling mailbox is judged "+
			"against its habit rather than a global number. Source addresses are not blocked because "+
			"they rotate and may include the owner's own; a Critical finding suspends the mailbox's "+
			"logins and outgoing mail under the auto-response settings.",
		user, hourIPs, len(hourCountries),
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

// runSenderProfileMaintenance saves dirty profiles independently of mail
// throughput. Shutdown performs a final save after the log readers stop.
func runSenderProfileMaintenance(stopCh <-chan struct{}) {
	ticker := time.NewTicker(senderFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case now := <-ticker.C:
			flushSenderProfiles()
			evictSenderWindows(now)
		}
	}
}

func flushSenderProfiles() {
	senderWindows.Range(func(key, val any) bool {
		w := val.(*senderWindow)
		w.mu.Lock()
		w.flush(key.(string))
		w.mu.Unlock()
		return true
	})
}

// Caller holds mu through the save: clearing dirty must never erase a
// concurrent submission, and eviction must not discard an unsaved profile.
func (w *senderWindow) flush(user string) bool {
	if !w.dirty || w.db == nil {
		return true
	}
	if err := w.db.SetSenderProfile(user, w.profile); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Warning: failed to save sender profile for %s: %v\n",
			time.Now().Format("2006-01-02 15:04:05"), user, err)
		return false
	}
	w.dirty = false
	return true
}

func evictSenderWindows(now time.Time) {
	cutoff := now.Add(-senderEvictWindow)
	senderWindows.Range(func(key, val any) bool {
		w := val.(*senderWindow)
		w.mu.Lock()
		if w.lastEvent.Before(cutoff) && w.flush(key.(string)) {
			senderWindows.CompareAndDelete(key, val)
		}
		w.mu.Unlock()
		return true
	})
	pruneSenderHistory(now)
}

var senderHistoryPrune struct {
	sync.Mutex
	db  *store.DB
	day string
}

func pruneSenderHistory(now time.Time) {
	db := store.Global()
	if db == nil {
		return
	}
	senderHistoryPrune.Lock()
	defer senderHistoryPrune.Unlock()
	today := senderDayKey(now)
	if senderHistoryPrune.db == db && senderHistoryPrune.day == today {
		return
	}
	oldest := senderDayKey(now.UTC().AddDate(0, 0, -senderBaselineDays))
	if err := db.PruneSenderProfiles(oldest); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Warning: failed to expire sender history: %v\n",
			now.Format("2006-01-02 15:04:05"), err)
		return
	}
	senderHistoryPrune.db, senderHistoryPrune.day = db, today
}

func (w *senderWindow) observeSource(now time.Time, ip, country string) {
	cutoff := now.Add(-senderHourWindow)
	kept := w.events[:0]
	for _, e := range w.events {
		if e.at.After(cutoff) && e.ip != ip {
			kept = append(kept, e)
		}
	}
	// Store the last observation of each source, so repeated sends cannot
	// fill the cap or displace another source's still-active evidence.
	if len(kept) == senderMaxHourEvents {
		copy(kept, kept[1:])
		kept = kept[:len(kept)-1]
	}
	kept = append(kept, senderEvent{at: now, ip: ip})
	w.events = kept
	if w.countries == nil {
		w.countries = make(map[string]time.Time)
	}
	for c, at := range w.countries {
		if !at.After(cutoff) {
			delete(w.countries, c)
		}
	}
	// Countries have their own clock: source-cap eviction must not erase
	// evidence of travel while that country is still inside the hour.
	if country != "" {
		w.countries[country] = now
	}
}
