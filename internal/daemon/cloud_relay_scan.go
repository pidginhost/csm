package daemon

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

// --- Retrospective scan for cloud-relay credential abuse -----------------
//
// The realtime watcher in cloud_relay.go only catches traffic arriving
// AFTER CSM starts. A credential-abuse spam run can go for weeks before
// an operator notices (a real incident saw 230 outbound sends from one
// compromised account over 20 days before being flagged). This scanner replays
// the last N hours of exim_mainlog through the same rule, so on CSM
// startup any in-progress or recent compromise is surfaced immediately.
//
// Runs once at daemon startup. Not part of the tiered-check registry
// because it is purely an event-log replay; the realtime watcher owns
// live state thereafter.

// cloudRelayScanPathDefault is where cPanel exim writes its mainlog.
const cloudRelayScanPathDefault = "/var/log/exim_mainlog"

// Memory caps for the retro scan. A compromised account or a crafted log
// can otherwise grow byUser without bound. The thresholds are set well
// above the volume detector (cloudRelayHighVolumeEvents=15 in a 60-min
// window) so legitimate detection is unaffected; the caps only kick in
// for pathological volumes that would balloon memory.
const (
	cloudRelayScanMaxEventsPerUser = 5000
	cloudRelayScanMaxUsers         = 10000
)

// CloudRelayScanPath is the log file path scanned at startup. Exported
// via var (not const) for tests.
var CloudRelayScanPath = cloudRelayScanPathDefault

// ScanEximHistoryForCloudRelay replays the tail of exim_mainlog for the
// last `lookback` duration and returns a finding per mailbox that
// exceeds the cloud-relay thresholds. Safe to call from goroutines.
//
// The scanner respects EmailProtection.HighVolumeSenders and the
// detector-scoped EmailProtection.CloudRelay.AllowUsers / .AllowDomains
// allowlists, mirrors the realtime detector's thresholds exactly, and
// uses a per-user persistent marker in the global store to avoid
// re-emitting the same finding on successive restarts.
func ScanEximHistoryForCloudRelay(cfg *config.Config, logPath string, now time.Time, lookback time.Duration) []alert.Finding {
	if logPath == "" {
		logPath = CloudRelayScanPath
	}
	// #nosec G304 -- logPath is operator-configured / hardcoded to cPanel default.
	f, err := os.Open(logPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	since := now.Add(-lookback)
	byUser := make(map[string]*cloudRelayScanAccumulator)

	// Use bufio.Reader rather than bufio.Scanner: an exim line can
	// occasionally exceed whatever fixed Scanner buffer we set (e.g.
	// a spam run with a huge Base64 subject). Scanner returns an
	// ErrTooLong which aborts the whole loop — missing every later
	// compromise event. Reader.ReadString lets us skip oversized
	// lines and keep going.
	reader := bufio.NewReaderSize(f, 256*1024)
	for {
		line, rerr := reader.ReadString('\n')
		if len(line) > 0 {
			if line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			processCloudRelayScanLine(line, cfg, since, byUser)
		}
		if rerr == nil {
			continue
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if errors.Is(rerr, bufio.ErrBufferFull) {
			// Line longer than 256 KB — drain it and move on.
			// Real exim acceptance lines are well under 10 KB;
			// anything longer is almost certainly a pathological
			// subject we can't usefully parse anyway.
			if drainErr := drainUntilNewline(reader); drainErr != nil {
				break
			}
			continue
		}
		// Any other I/O error: stop cleanly, don't panic.
		break
	}

	users := make([]string, 0, len(byUser))
	for u := range byUser {
		users = append(users, u)
	}
	sort.Strings(users) // stable finding order

	var findings []alert.Finding
	for _, user := range users {
		acc := byUser[user]
		if acc == nil || !acc.reportable {
			continue
		}
		maxSends, maxDistinctIPs, fireAt, peakPTR := acc.bestSends, acc.bestDistinctIPs, acc.bestAt, acc.bestPTR
		multiIP := maxSends >= cloudRelayMinEvents && maxDistinctIPs >= cloudRelayMinDistinctIP
		volume := maxSends >= cloudRelayHighVolumeEvents
		if !multiIP && !volume {
			continue
		}

		// Persistent dedup: skip if we've already fired for this user
		// and no new event has landed since then.
		latestEvent := acc.latestEvent
		if alreadyReportedRetro(user, latestEvent) {
			continue
		}

		ips := acc.recentIPs
		if len(ips) == 0 {
			continue
		}
		recentIP := ips[0]

		msg := fmt.Sprintf(
			"RETRO: account %s sent %d authenticated messages from %d cloud-provider IPs (peak 60-min burst) in the last %d hours - credentials compromised - from %s",
			user, maxSends, maxDistinctIPs, int(lookback.Hours()), recentIP,
		)
		details := fmt.Sprintf(
			"Retrospective exim_mainlog scan at %s found a cloud-relay pattern:\n"+
				"  user: %s\n"+
				"  total cloud-PTR sends (%dh): %d\n"+
				"  peak 60-min window: %d sends / %d distinct IPs ending at %s\n"+
				"  peak PTR: %s\n"+
				"  distinct source IPs observed: %s\n\n"+
				"Outgoing mail has been auto-suspended. The most recent source IP "+
				"has been queued for auto-block; older IPs were not blocked because "+
				"rented-fleet addresses tend to be recycled outside a 2-hour window.",
			now.Format("2006-01-02 15:04:05"),
			user,
			int(lookback.Hours()),
			acc.total,
			maxSends, maxDistinctIPs, fireAt.Format("2006-01-02 15:04:05"),
			peakPTR,
			strings.Join(ips, ", "),
		)

		mailbox, domain, tenant := splitMailAccount(user)
		findings = append(findings, alert.Finding{
			Severity:  alert.Critical,
			Check:     "email_cloud_relay_abuse",
			Message:   msg,
			Details:   truncateDaemon(details, 900),
			Timestamp: now,
			SourceIP:  recentIP,
			Mailbox:   mailbox,
			Domain:    domain,
			TenantID:  tenant,
		})

		markReportedRetro(user, latestEvent)
	}

	return findings
}

// processCloudRelayScanLine parses a single exim log line and, if it is
// an authenticated cloud-PTR acceptance within the lookback window,
// records it under the AUTH user in `byUser`.
func processCloudRelayScanLine(line string, cfg *config.Config, since time.Time, byUser map[string]*cloudRelayScanAccumulator) {
	if !strings.Contains(line, " <= ") || !strings.Contains(line, "A=dovecot_") {
		return
	}
	ts, ok := parseEximTimestamp(line)
	if !ok || ts.Before(since) {
		return
	}
	user := extractAuthUser(line)
	if user == "" || isHighVolumeSender(user, cfg.EmailProtection.HighVolumeSenders) {
		return
	}
	if isCloudRelayAllowed(user, cfg.EmailProtection.CloudRelay.AllowUsers, cfg.EmailProtection.CloudRelay.AllowDomains) {
		return
	}
	ptr := extractEximHostname(line)
	if !isCloudProviderPTR(ptr) {
		return
	}
	ip := extractBracketedIP(line)
	if ip == "" {
		return
	}

	acc, exists := byUser[user]
	if !exists {
		if len(byUser) >= cloudRelayScanMaxUsers {
			pruneCloudRelayScanUsers(byUser, ts)
		}
		if len(byUser) >= cloudRelayScanMaxUsers {
			evictOldestCloudRelayScanUser(byUser)
		}
		if len(byUser) >= cloudRelayScanMaxUsers {
			return
		}
		acc = newCloudRelayScanAccumulator()
		byUser[user] = acc
	}
	acc.record(cloudRelayScanEvent{at: ts, ip: ip, ptr: ptr})
}

// drainUntilNewline reads from reader and discards bytes until a newline
// is consumed or EOF is hit. Returns io.EOF if the reader is exhausted.
func drainUntilNewline(reader *bufio.Reader) error {
	for {
		_, err := reader.ReadSlice('\n')
		if err == nil {
			return nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			// Still inside the oversized line — keep draining.
			continue
		}
		return err
	}
}

// cloudRelayScanEvent is a single timestamped cloud-PTR AUTH send
// replayed from the log.
type cloudRelayScanEvent struct {
	at  time.Time
	ip  string
	ptr string
}

type cloudRelayScanAccumulator struct {
	events          []cloudRelayScanEvent
	ipCounts        map[string]int
	recentIPs       []string
	total           int
	latestEvent     time.Time
	bestSends       int
	bestDistinctIPs int
	bestAt          time.Time
	bestPTR         string
	reportable      bool
}

func newCloudRelayScanAccumulator() *cloudRelayScanAccumulator {
	return &cloudRelayScanAccumulator{
		ipCounts: make(map[string]int),
	}
}

func (acc *cloudRelayScanAccumulator) record(event cloudRelayScanEvent) {
	acc.total++
	if acc.latestEvent.IsZero() || event.at.After(acc.latestEvent) {
		acc.latestEvent = event.at
	}
	acc.rememberRecentIP(event.ip)

	cutoff := event.at.Add(-cloudRelayWindow_)
	drop := 0
	for drop < len(acc.events) && acc.events[drop].at.Before(cutoff) {
		acc.removeWindowIP(acc.events[drop].ip)
		drop++
	}
	if drop > 0 {
		clear(acc.events[:drop])
		acc.events = acc.events[drop:]
	}
	if len(acc.events) >= cloudRelayScanMaxEventsPerUser {
		acc.removeWindowIP(acc.events[0].ip)
		var zero cloudRelayScanEvent
		acc.events[0] = zero
		acc.events = acc.events[1:]
	}

	acc.events = append(acc.events, event)
	acc.ipCounts[event.ip]++

	sends := len(acc.events)
	distinctIPs := len(acc.ipCounts)
	if sends > acc.bestSends || (sends == acc.bestSends && distinctIPs > acc.bestDistinctIPs) {
		acc.bestSends = sends
		acc.bestDistinctIPs = distinctIPs
		acc.bestAt = event.at
		acc.bestPTR = event.ptr
	}
	if acc.bestSends >= cloudRelayHighVolumeEvents ||
		(acc.bestSends >= cloudRelayMinEvents && acc.bestDistinctIPs >= cloudRelayMinDistinctIP) {
		acc.reportable = true
	}
}

func (acc *cloudRelayScanAccumulator) removeWindowIP(ip string) {
	count := acc.ipCounts[ip]
	if count <= 1 {
		delete(acc.ipCounts, ip)
		return
	}
	acc.ipCounts[ip] = count - 1
}

func (acc *cloudRelayScanAccumulator) rememberRecentIP(ip string) {
	if ip == "" {
		return
	}
	for i, existing := range acc.recentIPs {
		if existing != ip {
			continue
		}
		copy(acc.recentIPs[1:i+1], acc.recentIPs[:i])
		acc.recentIPs[0] = ip
		return
	}
	acc.recentIPs = append(acc.recentIPs, "")
	copy(acc.recentIPs[1:], acc.recentIPs[:len(acc.recentIPs)-1])
	acc.recentIPs[0] = ip
	if len(acc.recentIPs) > 10 {
		acc.recentIPs = acc.recentIPs[:10]
	}
}

func pruneCloudRelayScanUsers(byUser map[string]*cloudRelayScanAccumulator, now time.Time) {
	cutoff := now.Add(-cloudRelayWindow_)
	for user, acc := range byUser {
		if acc == nil || (!acc.reportable && acc.latestEvent.Before(cutoff)) {
			delete(byUser, user)
		}
	}
}

func evictOldestCloudRelayScanUser(byUser map[string]*cloudRelayScanAccumulator) {
	var oldestUser string
	var oldestSeen time.Time
	for user, acc := range byUser {
		if acc == nil {
			delete(byUser, user)
			return
		}
		if acc.reportable {
			continue
		}
		if oldestUser == "" || acc.latestEvent.Before(oldestSeen) {
			oldestUser = user
			oldestSeen = acc.latestEvent
		}
	}
	if oldestUser != "" {
		delete(byUser, oldestUser)
	}
}

// maxCloudRelayBurst finds the strongest 60-min window in a sorted event
// list. Returns (sends, distinctIPs, peakEnd, peakPTR), where peakEnd is
// the timestamp of the LAST event in the best window so operators see
// when the burst peaked, not when it started.
func maxCloudRelayBurst(events []cloudRelayScanEvent) (int, int, time.Time, string) {
	if len(events) == 0 {
		return 0, 0, time.Time{}, ""
	}
	bestSends, bestDistinct := 0, 0
	var bestAt time.Time
	var bestPTR string
	left := 0
	ipCounts := make(map[string]int)
	for right, event := range events {
		ipCounts[event.ip]++
		for event.at.Sub(events[left].at) > cloudRelayWindow_ {
			leftIP := events[left].ip
			if ipCounts[leftIP] <= 1 {
				delete(ipCounts, leftIP)
			} else {
				ipCounts[leftIP]--
			}
			left++
		}
		sends := right - left + 1
		distinct := len(ipCounts)
		// "Best" = highest send count; tie-break by distinct IPs.
		if sends > bestSends || (sends == bestSends && distinct > bestDistinct) {
			bestSends = sends
			bestDistinct = distinct
			bestAt = event.at
			bestPTR = event.ptr
		}
	}
	return bestSends, bestDistinct, bestAt, bestPTR
}

// parseEximTimestamp extracts the "YYYY-MM-DD HH:MM:SS" timestamp prefix
// from an exim log line. Returns false on any parse failure.
func parseEximTimestamp(line string) (time.Time, bool) {
	if len(line) < 19 {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", line[:19], time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// alreadyReportedRetro returns true when the latest event for this user
// is older than or equal to the persisted marker (meaning: nothing new
// since we last alerted).
func alreadyReportedRetro(user string, latestEvent time.Time) bool {
	db := store.Global()
	if db == nil {
		return false
	}
	raw := db.GetMetaString("cloudrelay_retro:" + user)
	if raw == "" {
		return false
	}
	prev, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	return !latestEvent.After(prev)
}

// extractSenderFromCloudRelayMessage pulls the sender mailbox out of a
// finding message emitted by ScanEximHistoryForCloudRelay. Returns ""
// when the message is not from this check (defensive — never panics on
// unexpected input).
func extractSenderFromCloudRelayMessage(msg string) string {
	const marker = "account "
	idx := strings.Index(msg, marker)
	if idx < 0 {
		return ""
	}
	rest := msg[idx+len(marker):]
	sp := strings.IndexByte(rest, ' ')
	if sp <= 0 {
		return ""
	}
	candidate := rest[:sp]
	if !strings.Contains(candidate, "@") {
		return ""
	}
	return candidate
}

func markReportedRetro(user string, latestEvent time.Time) {
	db := store.Global()
	if db == nil {
		return
	}
	_ = db.SetMetaString("cloudrelay_retro:"+user, latestEvent.Format(time.RFC3339))
}
