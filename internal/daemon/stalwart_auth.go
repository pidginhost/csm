package daemon

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/stalwartlog"
)

// stalwartAuth feeds one Stalwart login event to the tracker for its
// listener's protocol. SMTP, IMAP, POP3 and ManageSieve listeners log the
// connecting peer, so their events reach the trackers that may block. An
// HTTP listener (JMAP, webmail) can log a forwarded address: its failures
// only alert, and its successes are not evidence of anything.
func (d *Daemon) stalwartAuth(ev stalwartlog.Event, s stalwartlog.Session, obs alert.Observation, cfg *config.Config) []alert.Finding {
	ip := s.RemoteIP.String()
	if isInfraIPDaemon(ip, cfg.InfraIPs) || isPrivateOrLoopback(ip) {
		return nil
	}
	account := ev.Fields["accountName"]
	success := ev.Name == "auth.success"
	if success && account == "" {
		return nil
	}
	switch proto := d.stalwart.ports.Of(s.LocalPort); proto {
	case stalwartlog.ProtoSMTP:
		if d.smtpAuthTracker == nil {
			return nil
		}
		if success {
			return d.smtpAuthTracker.recordSuccessAt(ip, account, ev.Time, serviceLog)
		}
		return d.smtpAuthTracker.RecordObserved(ip, account, obs)
	case stalwartlog.ProtoIMAP, stalwartlog.ProtoPOP3, stalwartlog.ProtoSieve:
		if d.mailAuthTracker == nil {
			return nil
		}
		if success {
			kind := knownCustomerIMAP
			if proto == stalwartlog.ProtoPOP3 {
				kind = knownCustomerPOP
			}
			return d.mailAuthTracker.recordSuccessAt(ip, account, ev.Time, kind)
		}
		return d.mailAuthTracker.RecordObserved(ip, account, obs)
	case stalwartlog.ProtoHTTP:
		if success {
			return nil
		}
		return d.stalwart.webmail.record(ip, ev.Time, cfg)
	}
	return nil
}

// stalwartWebmailMaxTracked bounds the tracker when no mail brute-force cap
// is configured.
const stalwartWebmailMaxTracked = 20000

// stalwartWebmailTracker counts failed logins on Stalwart's HTTP listener per
// address, with the mail brute-force threshold, window and suppression. Its
// findings carry no attribution and have no block policy.
type stalwartWebmailTracker struct {
	mu  sync.Mutex
	ips map[string]*stalwartWebmailEntry
}

type stalwartWebmailEntry struct {
	times      []time.Time
	lastSeen   time.Time
	quietUntil time.Time
}

func newStalwartWebmailTracker() *stalwartWebmailTracker {
	return &stalwartWebmailTracker{ips: map[string]*stalwartWebmailEntry{}}
}

func (t *stalwartWebmailTracker) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.ips)
}

// record counts one failure from ip at now and returns a finding when the
// address reaches the threshold within the window.
func (t *stalwartWebmailTracker) record(ip string, now time.Time, cfg *config.Config) []alert.Finding {
	th := cfg.Thresholds
	window := time.Duration(th.MailBruteForceWindowMin) * time.Minute
	if th.MailBruteForceThreshold <= 0 || window <= 0 {
		return nil
	}
	maxTracked := th.MailBruteForceMaxTracked
	if maxTracked <= 0 {
		maxTracked = stalwartWebmailMaxTracked
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.ips[ip]
	if e == nil {
		t.evictFor(maxTracked)
		e = &stalwartWebmailEntry{}
		t.ips[ip] = e
	}
	e.lastSeen = now
	if now.Before(e.quietUntil) {
		return nil
	}
	e.times = append(pruneTimes(e.times, now.Add(-window)), now)
	n := len(e.times)
	if n < th.MailBruteForceThreshold {
		return nil
	}
	e.times = nil
	e.quietUntil = now.Add(time.Duration(th.MailBruteForceSuppressMin) * time.Minute)
	return []alert.Finding{{
		Severity: alert.High,
		Check:    "stalwart_webmail_bruteforce",
		Message:  fmt.Sprintf("Webmail or JMAP login failures from %s: %d in %d minutes (Stalwart)", ip, n, th.MailBruteForceWindowMin),
		Details: "Stalwart's HTTP listener can log an address taken from a forwarded header, " +
			"so CSM reports it and does not block it. Stalwart applies its own throttling and bans to this address.",
		Timestamp: now,
		SourceIP:  ip,
	}}
}

// evictFor makes room for one more address. At the cap it drops the least
// recently seen tenth in one pass, so a flood of new addresses costs one sort
// per tenth of the cap rather than a full scan per address.
func (t *stalwartWebmailTracker) evictFor(maxTracked int) {
	if len(t.ips) < maxTracked {
		return
	}
	type seen struct {
		ip string
		at time.Time
	}
	all := make([]seen, 0, len(t.ips))
	for ip, e := range t.ips {
		all = append(all, seen{ip, e.lastSeen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	drop := len(all) - maxTracked*9/10
	if drop < 1 {
		drop = 1
	}
	for _, s := range all[:min(drop, len(all))] {
		delete(t.ips, s.ip)
	}
}

// stalwartBanReasons names the Stalwart bans CSM follows. A loiter ban is
// left out because slow legitimate mail servers trigger it.
var stalwartBanReasons = map[string]string{
	"security.authentication-ban": "repeated failed logins",
	"security.abuse-ban":          "abuse",
	"security.scan-ban":           "scanning",
}

// stalwartBan turns a Stalwart ban on a mail listener into a finding that
// blocks the address at CSM's firewall. A ban on the HTTP listener or an
// unmapped port may name a forwarded address and is not followed.
func (d *Daemon) stalwartBan(ev stalwartlog.Event, s stalwartlog.Session, cfg *config.Config) []alert.Finding {
	what, ok := stalwartBanReasons[ev.Name]
	if !ok {
		return nil
	}
	proto := d.stalwart.ports.Of(s.LocalPort)
	switch proto {
	case stalwartlog.ProtoSMTP, stalwartlog.ProtoIMAP, stalwartlog.ProtoPOP3, stalwartlog.ProtoSieve:
	default:
		return nil
	}
	ip := s.RemoteIP.String()
	if isInfraIPDaemon(ip, cfg.InfraIPs) || isPrivateOrLoopback(ip) {
		return nil
	}
	if reason := ev.Fields["reason"]; reason != "" {
		what += ": " + reason
	}
	f := alert.Finding{
		Severity:    alert.Critical,
		Check:       "stalwart_ban",
		Message:     fmt.Sprintf("Stalwart banned %s on its %s listener (port %d) for %s", ip, proto, s.LocalPort, what),
		Details:     "CSM blocks the address at its firewall for the auto-response block length. Stalwart's own ban stays in place.",
		Timestamp:   ev.Time,
		SourceIP:    ip,
		Attribution: admission.AttributionPeer,
	}
	// A failed-login ban of an address a customer logged in from recently is
	// most likely an office network with one stale password, or failures
	// another listener attributed to it. Only Critical bans block, so this
	// one is reported and not blocked. Scanning and abuse are never a
	// customer's own mistake. On a Stalwart host the customer logins come
	// from Stalwart's log, which only stalwart and root can write. Stalwart's
	// bans expire, so only the first ban within the known-customer window is
	// excused: an address banned again keeps failing and is blocked.
	if _, known := d.knownCustomers.Lookup(ip); known && ev.Name == "security.authentication-ban" &&
		d.stalwart.excused.first(s.RemoteIP, ev.Time) {
		f.Severity = alert.High
		f.Message += "; not blocked, a customer logged in from this address recently"
		f.Details = "A customer logged in successfully from this address within the last 30 days, so CSM reports " +
			"Stalwart's ban without blocking the address at its firewall. Stalwart's own ban still refuses its mail connections."
	}
	return []alert.Finding{f}
}

// excusedBans remembers when a known customer's address last had a
// failed-login ban excused.
type excusedBans struct {
	mu sync.Mutex
	at map[netip.Addr]time.Time
}

// first reports whether ip has had no ban excused within knownCustomerTTL
// of now, and records now when it has not. It holds at most
// maxKnownCustomers addresses, dropping expired ones first, then the oldest.
func (e *excusedBans) first(ip netip.Addr, now time.Time) bool {
	ip = ip.Unmap()
	e.mu.Lock()
	defer e.mu.Unlock()
	if last, ok := e.at[ip]; ok && now.Sub(last) < knownCustomerTTL {
		return false
	}
	if e.at == nil {
		e.at = map[netip.Addr]time.Time{}
	}
	if _, ok := e.at[ip]; !ok && len(e.at) >= maxKnownCustomers {
		e.evict(now)
	}
	e.at[ip] = now
	return true
}

// evict drops expired entries and, if that frees nothing, the oldest tenth,
// so a full set costs one sort per tenth of the cap rather than one per ban.
func (e *excusedBans) evict(now time.Time) {
	for ip, at := range e.at {
		if now.Sub(at) >= knownCustomerTTL {
			delete(e.at, ip)
		}
	}
	if len(e.at) < maxKnownCustomers {
		return
	}
	type entry struct {
		ip netip.Addr
		at time.Time
	}
	all := make([]entry, 0, len(e.at))
	for ip, at := range e.at {
		all = append(all, entry{ip, at})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for _, x := range all[:len(all)-maxKnownCustomers*9/10] {
		delete(e.at, x.ip)
	}
}

func (e *excusedBans) size() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.at)
}
