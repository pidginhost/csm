package daemon

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// smtpProbeBlockExpiryString returns the configured block expiry string when
// auto-response will actually block the source IP for an `smtp_probe_abuse`
// finding (auto_response.enabled AND block_ips true AND dry_run false), or ""
// otherwise.
// The returned string is what the operator put in csm.yaml ("24h", "12h"...)
// so the alert text matches the value they configured rather than Go's
// canonical Duration formatting.
func smtpProbeBlockExpiryString() string {
	cfg := config.Active()
	if cfg == nil {
		return ""
	}
	if !cfg.AutoResponse.Enabled || !cfg.AutoResponse.BlockIPs || cfg.AutoResponseDryRunEnabled() {
		return ""
	}
	if cfg.AutoResponse.BlockExpiry == "" {
		return "24h"
	}
	return cfg.AutoResponse.BlockExpiry
}

// smtpProbeEntry records connect timestamps and suppression for one IP.
type smtpProbeEntry struct {
	times      []time.Time
	suppressed time.Time
	lastSeen   time.Time
}

// smtpProbeTracker counts raw SMTP connect events per source IP and emits an
// `smtp_probe_abuse` finding when an IP exceeds the threshold inside the
// rolling window.
//
// This is the connection-rate complement to smtpAuthTracker: scanners that
// probe-and-disconnect (no AUTH attempt) never trigger the auth tracker, so
// they need their own signal. The thresholds are deliberately set well above
// any legitimate MUA usage; Thunderbird/iPhone bursts of 10-15 parallel
// sessions per send fall comfortably under, scanner storms with hundreds of
// connect/min are caught.
type smtpProbeTracker struct {
	mu sync.Mutex

	threshold   int
	window      time.Duration
	suppression time.Duration
	maxTracked  int
	now         func() time.Time

	// expiryStrFn returns the operator-visible block expiry (e.g. "24h") when
	// live auto-blocking is enabled, or "" when no auto-block will run. Read
	// at finding time so a SIGHUP reload of auto_response.* is reflected in
	// the next emitted finding's Details.
	expiryStrFn func() string

	ips map[string]*smtpProbeEntry
}

func newSMTPProbeTracker(threshold int, window, suppression time.Duration, maxTracked int, now func() time.Time, expiryStrFn func() string) *smtpProbeTracker {
	if now == nil {
		now = time.Now
	}
	return &smtpProbeTracker{
		threshold:   threshold,
		window:      window,
		suppression: suppression,
		maxTracked:  maxTracked,
		now:         now,
		expiryStrFn: expiryStrFn,
		ips:         make(map[string]*smtpProbeEntry),
	}
}

// Size returns the number of tracked source IPs.
func (t *smtpProbeTracker) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.ips)
}

// Record observes one SMTP connect event. ip MUST be non-private,
// non-loopback, and non-infra. Callers enforce this before invoking Record.
// Returns zero or one finding (no per-call multiplication).
func (t *smtpProbeTracker) Record(ip string) []alert.Finding {
	if ip == "" || t.threshold <= 0 {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	cutoff := now.Add(-t.window)

	e, ok := t.ips[ip]
	if !ok {
		e = &smtpProbeEntry{}
		t.ips[ip] = e
	}
	e.times = pruneTimes(e.times, cutoff)
	e.times = append(e.times, now)
	e.lastSeen = now

	var findings []alert.Finding
	if len(e.times) >= t.threshold && !now.Before(e.suppressed) {
		e.suppressed = now.Add(t.suppression)
		// The Details message is computed here, before AutoBlockIPs runs in
		// dispatchBatch. We can only report the *intent* (scheduled for
		// auto-block) - the actual outcome (blocked / rate-limited / already
		// blocked / challenged) is published by the companion `auto_block`
		// finding emitted by checks.AutoBlockIPs in the same batch.
		details := "Sustained SMTP connect rate above the configured threshold. Likely scanner / dictionary probe;"
		if t.expiryStrFn != nil {
			if exp := t.expiryStrFn(); exp != "" {
				details += fmt.Sprintf(" scheduled for auto-block (%s).", exp)
			} else {
				details += " consider manual block."
			}
		} else {
			details += " consider manual block."
		}
		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "smtp_probe_abuse",
			Message: fmt.Sprintf("SMTP probe abuse from %s: %d connections in %v",
				ip, len(e.times), t.window),
			Details:   details,
			Timestamp: now,
			SourceIP:  ip,
		})
	}

	t.enforceMaxTracked()
	return findings
}

// Purge removes IPs with no activity since (window + suppression) ago.
// Called periodically to prevent unbounded growth.
func (t *smtpProbeTracker) Purge() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	activityCutoff := now.Add(-(t.window + t.suppression))
	for k, e := range t.ips {
		e.times = pruneTimes(e.times, now.Add(-t.window))
		if len(e.times) == 0 && !e.lastSeen.After(activityCutoff) {
			delete(t.ips, k)
		}
	}
}

// enforceMaxTracked evicts the least-recently-seen IPs to keep memory bounded.
// Caller must hold t.mu.
func (t *smtpProbeTracker) enforceMaxTracked() {
	if t.maxTracked <= 0 || len(t.ips) <= t.maxTracked {
		return
	}
	type victim struct {
		key  string
		seen time.Time
	}
	victims := make([]victim, 0, len(t.ips))
	for k, e := range t.ips {
		victims = append(victims, victim{k, e.lastSeen})
	}
	sort.Slice(victims, func(i, j int) bool { return victims[i].seen.Before(victims[j].seen) })
	target := t.maxTracked * 95 / 100
	for i := 0; i < len(victims) && len(t.ips) > target; i++ {
		delete(t.ips, victims[i].key)
	}
}

// parseEximSMTPConnectIP extracts the connecting source IP from an exim
// mainlog "SMTP connection from ..." line. Returns "" when the line is not
// a connect event.
//
// Exim formats vary:
//
//	SMTP connection from [1.2.3.4]:65417 (TCP/IP connection count = 7)
//	SMTP connection from (helo.example.com) [1.2.3.4]:43018 lost D=5s
//	SMTP connection from ([helo-as-ip]) [1.2.3.4]:38294 lost D=15s
//	SMTP connection from ([192.168.0.94]) [1.2.3.4]:64547 D=5s closed by QUIT
//
// The connecting peer is always the LAST `[ip]:port` token before flags.
func parseEximSMTPConnectIP(line string) string {
	const marker = "SMTP connection from "
	idx := strings.Index(line, marker)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(marker):]

	// Walk all `[...]` tokens; remember the last one whose `:port` follows.
	var last string
	for {
		open := strings.Index(rest, "[")
		if open < 0 {
			break
		}
		close := strings.Index(rest[open:], "]")
		if close < 0 {
			break
		}
		candidate := rest[open+1 : open+close]
		afterClose := rest[open+close+1:]
		if strings.HasPrefix(afterClose, ":") {
			// Confirm digits follow the colon; that is the source port.
			tail := afterClose[1:]
			if len(tail) > 0 && tail[0] >= '0' && tail[0] <= '9' {
				last = candidate
			}
		}
		rest = afterClose
	}
	return last
}
