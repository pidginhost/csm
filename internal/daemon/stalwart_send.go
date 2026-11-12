package daemon

import (
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/stalwartlog"
)

const (
	// stalwartSessionTTL is how long a login names the sends on its
	// connection; each send refreshes it.
	stalwartSessionTTL = time.Hour
	// stalwartSessionMax bounds the connections remembered.
	stalwartSessionMax = 4096
)

// stalwartNoSuspendContext tells staff that a Stalwart mailbox stays active.
const stalwartNoSuspendContext = "This version of CSM cannot suspend Stalwart mailboxes; change the mailbox password in Stalwart."

// stalwartPTR is the reverse DNS name of an address. var so tests can stand
// in for DNS.
var stalwartPTR = func(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	return rdnsCache().Lookup(parsed)
}

// stalwartSessions remembers which account logged in on each connection.
// Stalwart logs a queued message with the connection but not the account,
// so the login on the same listener, client address and client port names
// the sender.
type stalwartSessions struct {
	mu sync.Mutex
	m  map[string]stalwartSession
}

type stalwartSession struct {
	account string
	at      time.Time
}

func newStalwartSessions() *stalwartSessions {
	return &stalwartSessions{m: map[string]stalwartSession{}}
}

func stalwartSessionKey(s stalwartlog.Session) string {
	return s.Listener + "|" + s.RemoteIP.String() + "|" + strconv.Itoa(int(s.RemotePort))
}

func (s *stalwartSessions) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// remember records that account logged in on the connection key at at.
func (s *stalwartSessions) remember(key, account string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[key]; !ok && len(s.m) >= stalwartSessionMax {
		s.evictLocked(at)
	}
	s.m[key] = stalwartSession{account: account, at: at}
}

// account returns the account logged in on key, refreshing its age.
func (s *stalwartSessions) account(key string, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[key]
	if !ok || now.Sub(e.at) >= stalwartSessionTTL {
		return "", false
	}
	if now.After(e.at) {
		e.at = now
		s.m[key] = e
	}
	return e.account, true
}

// evictLocked drops expired connections, then the oldest tenth if the map
// is still full, so a burst of logins costs one sort per tenth of the cap.
func (s *stalwartSessions) evictLocked(now time.Time) {
	for k, e := range s.m {
		if now.Sub(e.at) >= stalwartSessionTTL {
			delete(s.m, k)
		}
	}
	if len(s.m) < stalwartSessionMax {
		return
	}
	keys := make([]string, 0, len(s.m))
	for k := range s.m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return s.m[keys[i]].at.Before(s.m[keys[j]].at) })
	for _, k := range keys[:len(keys)-stalwartSessionMax*9/10] {
		delete(s.m, k)
	}
}

// stalwartSend feeds one authenticated send to the rate, sender-profile and
// cloud-relay detectors. Only a send on an SMTP listener from a public
// address carries an address signal; a local or HTTP-listener send counts
// toward volume and recipients only.
func (d *Daemon) stalwartSend(ev stalwartlog.Event, s stalwartlog.Session, cfg *config.Config) []alert.Finding {
	st := d.stalwart
	account, ok := st.sessions.account(stalwartSessionKey(s), ev.Time)
	if !ok {
		st.stats.unattributed.Add(1)
		return nil
	}
	signalIP := ""
	if ip := s.RemoteIP.String(); st.ports.Of(s.LocalPort) == stalwartlog.ProtoSMTP && !isPrivateOrLoopback(ip) && !isInfraIPDaemon(ip, cfg.InfraIPs) {
		signalIP = ip
	}
	now := time.Now()
	findings := checkEmailRate(account, cfg)
	for _, f := range senderProfileObserve(cfg, account, signalIP, ev.Lists["to"], now) {
		if f.Severity == alert.Critical {
			respondToStalwartCompromise(cfg, account, "email_compromised_account", "authenticated sends outside the mailbox's own source and recipient history", f.Timestamp)
		}
		f.Context = stalwartNoSuspendContext
		findings = append(findings, f)
	}
	if signalIP != "" {
		for _, f := range cloudRelayObserve(cfg, account, signalIP, stalwartPTR(signalIP), now) {
			respondToStalwartCompromise(cfg, account, "email_cloud_relay_abuse", "authenticated sends from several cloud-provider addresses", f.Timestamp)
			f.Context = stalwartNoSuspendContext
			findings = append(findings, f)
		}
	}
	return findings
}

// respondToStalwartCompromise responds to a compromised Stalwart account. A
// bare account name has no domain to mark, and the envelope sender is the
// sender's own choice: marking its domain would only quiet other mailboxes'
// rate alerts. The finding stands either way.
func respondToStalwartCompromise(cfg *config.Config, account, check, reason string, at time.Time) {
	if extractDomainFromEmail(account) != "" {
		respondToMailboxCompromise(cfg, account, check, reason, at)
	}
}
