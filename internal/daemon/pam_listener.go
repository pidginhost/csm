package daemon

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

const pamSocketPath = "/var/run/csm/pam.sock"

// PAMListener listens on a Unix socket for authentication events from the
// pam_csm.so PAM module. Tracks failures per IP and triggers CSM auto-blocking.
type PAMListener struct {
	cfg      *config.Config
	alertCh  chan<- alert.Finding
	listener net.Listener
	mu       sync.Mutex
	failures map[string]*pamFailureTracker
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

	// Allow the PAM module (running as various users) to connect
	_ = os.Chmod(pamSocketPath, 0666)

	return &PAMListener{
		cfg:      cfg,
		alertCh:  alertCh,
		listener: listener,
		failures: make(map[string]*pamFailureTracker),
	}, nil
}

// Run accepts connections and processes PAM events.
func (p *PAMListener) Run(stopCh <-chan struct{}) {
	// Start cleanup goroutine to expire old failure records
	go p.cleanupLoop(stopCh)

	// Accept connections
	go func() {
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
			go p.handleConnection(conn)
		}
	}()

	<-stopCh
}

// Stop closes the listener and removes the socket file.
func (p *PAMListener) Stop() {
	_ = p.listener.Close()
	os.Remove(pamSocketPath)
}

func (p *PAMListener) handleConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()
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
		p.recordFailure(ip, user, service)
	case "OK":
		// Successful login from non-infra IP - informational alert
		p.alertCh <- alert.Finding{
			Severity:  alert.High,
			Check:     "pam_login",
			Message:   fmt.Sprintf("Login success from non-infra IP: %s (user: %s, service: %s)", ip, user, service),
			Timestamp: time.Now(),
		}
	}
}

func (p *PAMListener) recordFailure(ip, user, service string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	tracker, exists := p.failures[ip]
	if !exists {
		tracker = &pamFailureTracker{
			firstSeen: time.Now(),
			users:     make(map[string]bool),
			services:  make(map[string]bool),
		}
		p.failures[ip] = tracker
	}

	tracker.count++
	tracker.lastSeen = time.Now()
	tracker.users[user] = true
	tracker.services[service] = true

	// Check threshold
	threshold := 5
	windowMin := 10
	if p.cfg.Thresholds.MultiIPLoginThreshold > 0 {
		threshold = p.cfg.Thresholds.MultiIPLoginThreshold
	}

	// Only block if within the time window
	if time.Since(tracker.firstSeen) > time.Duration(windowMin)*time.Minute {
		// Window expired - reset tracker
		tracker.count = 1
		tracker.firstSeen = time.Now()
		tracker.users = map[string]bool{user: true}
		tracker.services = map[string]bool{service: true}
		tracker.blocked = false
		return
	}

	if tracker.count >= threshold && !tracker.blocked {
		tracker.blocked = true

		// Build user/service lists for details
		var users, services []string
		for u := range tracker.users {
			users = append(users, u)
		}
		for s := range tracker.services {
			services = append(services, s)
		}

		p.alertCh <- alert.Finding{
			Severity: alert.Critical,
			Check:    "pam_bruteforce",
			Message:  fmt.Sprintf("PAM brute-force detected: %s (%d failures in %ds)", ip, tracker.count, int(time.Since(tracker.firstSeen).Seconds())),
			Details: fmt.Sprintf("Users targeted: %s\nServices: %s",
				strings.Join(users, ", "), strings.Join(services, ", ")),
			Timestamp: time.Now(),
		}
	}
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
			p.mu.Unlock()
		}
	}
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
