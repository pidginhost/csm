package daemon

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/health"
	"github.com/pidginhost/csm/internal/obs"
)

const pamSocketPath = "/var/run/csm/pam.sock"

const (
	defaultPAMFailureThreshold          = 5
	defaultPAMFailureWindowMin          = 10
	defaultCredStuffingDistinctAccounts = 5
)

// PAMListener listens on a Unix socket for authentication events from the
// pam_csm.so PAM module. Tracks failures per IP and triggers CSM auto-blocking.
type PAMListener struct {
	cfg      *config.Config
	alertCh  chan<- alert.Finding
	listener net.Listener
	mu       sync.Mutex
	failures map[string]*pamFailureTracker
	// stopCh is set by Run so emit can abort a send when the daemon is
	// shutting down. Per-connection goroutines are not tracked by a
	// WaitGroup, so without this escape a goroutine blocked on the
	// undrained alert channel would leak past shutdown. Nil for
	// hand-constructed listeners in tests, where emit keeps blocking-send
	// semantics.
	stopCh <-chan struct{}
	// useActiveConfig is true for the daemon-owned listener, so SIGHUP
	// threshold changes apply without rebuilding the socket. Unit tests that
	// assemble a listener by hand keep using their local cfg.
	useActiveConfig bool
	// stuffing flags one source IP failing against many distinct accounts
	// (credential stuffing / password spraying breadth) -- complementary to
	// the per-IP failure-count brute-force trigger below. Guarded by mu.
	stuffing *credentialStuffingDetector
	// startedAt anchors the upstream-probe verdict so the dashboard does
	// not flag a freshly-started daemon as "deaf" before the PAM module
	// has had a chance to emit anything. Compared against lastPeerNanos
	// to decide whether silence is informative.
	startedAt time.Time
	// lastPeerNanos is an atomic UnixNano timestamp updated on every
	// inbound connection (regardless of payload validity). Used by the
	// upstream probe to detect a missing PAM module hook.
	lastPeerNanos atomic.Int64
}

type pamFailureTracker struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
	users     map[string]bool
	services  map[string]bool
	blocked   bool
}

// NewPAMListener creates a Unix socket listener for PAM events.
func NewPAMListener(cfg *config.Config, alertCh chan<- alert.Finding) (*PAMListener, error) {
	// Ensure socket directory exists
	if err := os.MkdirAll("/var/run/csm", 0750); err != nil {
		return nil, fmt.Errorf("creating socket dir: %w", err)
	}

	// Remove stale socket
	os.Remove(pamSocketPath)

	listener, err := net.Listen("unix", pamSocketPath)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", pamSocketPath, err)
	}

	// The PAM module runs inside privileged auth stacks, so the socket can stay
	// root-only instead of accepting arbitrary local writers.
	_ = os.Chmod(pamSocketPath, 0600)

	_, window, distinct := pamThresholds(cfg)

	return &PAMListener{
		cfg:             cfg,
		alertCh:         alertCh,
		listener:        listener,
		failures:        make(map[string]*pamFailureTracker),
		startedAt:       time.Now(),
		useActiveConfig: true,
		stuffing:        newCredentialStuffingDetector(distinct, window, nil),
	}, nil
}

// UpstreamProbe returns an UpstreamResult describing whether the PAM
// module hook is feeding the socket. The probe is cheap (single atomic
// load + clock read) so it is safe to wire into the components API.
//
// Fresh verdict:
//   - At least one inbound connection within pamUpstreamFreshWindow.
//   - Or the daemon has been up for less than pamUpstreamGracePeriod
//     (so a freshly-started daemon is not flagged before the first
//     real auth happens).
//
// LastActivity is the most recent connection time, or the daemon start
// time when no connection has arrived. Reason explains a !Fresh verdict
// to operators.
func (p *PAMListener) UpstreamResult() health.UpstreamResult {
	last := time.Unix(0, p.lastPeerNanos.Load())
	if p.lastPeerNanos.Load() == 0 && time.Since(p.startedAt) < pamUpstreamGracePeriod {
		return health.UpstreamResult{Fresh: true, LastActivity: p.startedAt}
	}
	if p.lastPeerNanos.Load() != 0 && time.Since(last) < pamUpstreamFreshWindow {
		return health.UpstreamResult{Fresh: true, LastActivity: last}
	}
	reason := "no PAM module hook feeding the socket; install pam_csm.so and add `session optional pam_csm.so` to the relevant /etc/pam.d/ files"
	activity := last
	if p.lastPeerNanos.Load() == 0 {
		activity = p.startedAt
	}
	return health.UpstreamResult{Fresh: false, LastActivity: activity, Reason: reason}
}

const (
	// pamUpstreamFreshWindow is how recently a peer connection must have
	// arrived before the upstream is considered alive. Sized to comfortably
	// span the longest realistic gap between auth events on a host that
	// has the PAM module installed.
	pamUpstreamFreshWindow = 24 * time.Hour
	// pamUpstreamGracePeriod is the post-start window during which a
	// silent socket is not yet flagged as deaf.
	pamUpstreamGracePeriod = 15 * time.Minute
)

// Run accepts connections and processes PAM events.
func (p *PAMListener) Run(stopCh <-chan struct{}) {
	p.stopCh = stopCh
	// Start cleanup goroutine to expire old failure records
	obs.Go("pam-cleanup", func() { p.cleanupLoop(stopCh) })

	// Accept connections
	obs.Go("pam-accept", func() {
		for {
			conn, err := p.listener.Accept()
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
					fmt.Fprintf(os.Stderr, "[%s] PAM listener accept error: %v\n", ts(), err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}
			obs.SafeGo("pam-conn", func() { p.handleConnection(conn) })
		}
	})

	<-stopCh
}

// Stop closes the listener and removes the socket file.
func (p *PAMListener) Stop() {
	_ = p.listener.Close()
	os.Remove(pamSocketPath)
}

func (p *PAMListener) handleConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	// Record the connection moment regardless of peer trust so the
	// upstream probe can distinguish "PAM hook not installed" (no
	// connections at all) from "PAM hook present but rejected as
	// untrusted" (connections happen but never deliver payload).
	p.lastPeerNanos.Store(time.Now().UnixNano())
	if !isTrustedPAMPeer(conn) {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(1 * time.Second))

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		p.processEvent(line)
	}
}

// processEvent handles a single PAM event line.
// Format: FAIL ip=1.2.3.4 user=root service=sshd
//
//	OK ip=1.2.3.4 user=root service=sshd
func (p *PAMListener) processEvent(line string) {
	parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
	if len(parts) < 2 {
		return
	}

	eventType := parts[0]
	kvPart := parts[1]

	var ip, user, service string
	for _, kv := range strings.Fields(kvPart) {
		switch {
		case strings.HasPrefix(kv, "ip="):
			ip = kv[3:]
		case strings.HasPrefix(kv, "user="):
			user = kv[5:]
		case strings.HasPrefix(kv, "service="):
			service = kv[8:]
		}
	}

	if ip == "" || ip == "-" || ip == "127.0.0.1" {
		return
	}

	// Skip infra IPs
	if isInfraIP(ip, p.cfg.InfraIPs) {
		return
	}

	switch eventType {
	case "FAIL":
		p.emit(p.recordFailure(ip, user, service))
	case "OK":
		p.clearFailures(ip)
		// Successful login from non-infra IP - informational alert
		p.emit([]alert.Finding{{
			Severity:  alert.High,
			Check:     "pam_login",
			Message:   fmt.Sprintf("Login success from non-infra IP: %s (user: %s, service: %s)", ip, user, service),
			Timestamp: time.Now(),
			SourceIP:  ip,
		}})
	}
}

// emit forwards findings to the alert channel. It must be called WITHOUT
// p.mu held: a stalled alert consumer blocks the send, and holding the lock
// across that send would wedge recordFailure, clearFailures, and the cleanup
// loop, letting failure trackers grow without bound.
func (p *PAMListener) emit(findings []alert.Finding) {
	for _, f := range findings {
		select {
		case p.alertCh <- f:
		case <-p.stopCh:
			// Shutting down and the dispatcher has stopped draining;
			// drop the remaining findings rather than leak this
			// goroutine. A nil stopCh (hand-constructed listener)
			// makes this case unselectable, preserving blocking send.
			return
		}
	}
}

// recordFailure updates per-IP failure state and returns any findings the
// update produced. Findings are returned rather than sent so the caller can
// emit them after releasing p.mu (see emit).
func (p *PAMListener) recordFailure(ip, user, service string) []alert.Finding {
	p.mu.Lock()
	defer p.mu.Unlock()
	var findings []alert.Finding
	cfg := p.currentCfg()
	threshold, window, distinct := pamThresholds(cfg)
	now := time.Now()

	tracker, exists := p.failures[ip]
	if !exists {
		tracker = &pamFailureTracker{
			firstSeen: now,
			users:     make(map[string]bool),
			services:  make(map[string]bool),
		}
		p.failures[ip] = tracker
	}

	tracker.count++
	tracker.lastSeen = now
	tracker.users[user] = true
	tracker.services[service] = true

	// Credential-stuffing breadth signal: one source IP failing against many
	// distinct accounts. Independent of the per-IP failure-count brute-force
	// trigger below, so a low-and-slow campaign that stays under the count
	// threshold per account is still caught. Fires once per window.
	p.ensureCredentialStuffingDetectorLocked(distinct, window, now)
	if accounts, fire := p.stuffing.Record(ip, user); fire {
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "credential_stuffing",
			Message:  fmt.Sprintf("Credential stuffing: %s failed logins against %d distinct accounts", ip, len(accounts)),
			Details: fmt.Sprintf("Accounts targeted: %s\nService(s): %s",
				strings.Join(accounts, ", "), strings.Join(sortedBoolKeys(tracker.services), ", ")),
			Timestamp:    now,
			SourceIP:     ip,
			SprayTargets: append([]string(nil), accounts...),
		})
	}

	// Only block if within the time window
	if now.Sub(tracker.firstSeen) > window {
		// Window expired - reset tracker
		tracker.count = 1
		tracker.firstSeen = now
		tracker.users = map[string]bool{user: true}
		tracker.services = map[string]bool{service: true}
		tracker.blocked = false
		return findings
	}

	if tracker.count >= threshold && !tracker.blocked {
		tracker.blocked = true

		users := sortedBoolKeys(tracker.users)
		services := sortedBoolKeys(tracker.services)

		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "pam_bruteforce",
			Message:  fmt.Sprintf("PAM brute-force detected: %s (%d failures in %ds)", ip, tracker.count, int(now.Sub(tracker.firstSeen).Seconds())),
			Details: fmt.Sprintf("Users targeted: %s\nServices: %s",
				strings.Join(users, ", "), strings.Join(services, ", ")),
			Timestamp:    now,
			SourceIP:     ip,
			SprayTargets: users,
		})
	}

	return findings
}

func (p *PAMListener) clearFailures(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.failures, ip)
	p.stuffing.Clear(ip)
}

// cleanupLoop removes expired failure trackers every minute.
func (p *PAMListener) cleanupLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			p.mu.Lock()
			cutoff := time.Now().Add(-30 * time.Minute)
			for ip, tracker := range p.failures {
				if tracker.lastSeen.Before(cutoff) {
					delete(p.failures, ip)
				}
			}
			if p.stuffing != nil {
				now := time.Now()
				_, window, distinct := pamThresholds(p.currentCfg())
				p.stuffing.Configure(distinct, window, now)
				p.stuffing.PruneStale(now)
			}
			p.mu.Unlock()
		}
	}
}

func (p *PAMListener) currentCfg() *config.Config {
	if p.useActiveConfig {
		if cfg := config.Active(); cfg != nil {
			return cfg
		}
	}
	return p.cfg
}

func pamThresholds(cfg *config.Config) (threshold int, window time.Duration, distinct int) {
	threshold = defaultPAMFailureThreshold
	windowMin := defaultPAMFailureWindowMin
	distinct = defaultCredStuffingDistinctAccounts
	if cfg != nil {
		if cfg.Thresholds.MultiIPLoginThreshold > 0 {
			threshold = cfg.Thresholds.MultiIPLoginThreshold
		}
		if cfg.Thresholds.MultiIPLoginWindowMin > 0 {
			windowMin = cfg.Thresholds.MultiIPLoginWindowMin
		}
		if cfg.Thresholds.CredStuffingDistinctAccounts > 0 {
			distinct = cfg.Thresholds.CredStuffingDistinctAccounts
		}
	}
	return threshold, time.Duration(windowMin) * time.Minute, distinct
}

func (p *PAMListener) ensureCredentialStuffingDetectorLocked(distinct int, window time.Duration, now time.Time) {
	if p.stuffing == nil {
		p.stuffing = newCredentialStuffingDetector(distinct, window, nil)
		return
	}
	p.stuffing.Configure(distinct, window, now)
}

func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isInfraIP checks if an IP is in the configured infra IP ranges.
// Duplicated here to avoid import cycle with checks package.
func isInfraIP(ip string, infraNets []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range infraNets {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}
