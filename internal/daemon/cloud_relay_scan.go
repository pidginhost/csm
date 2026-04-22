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
// an operator notices (see: cluster6 Apr 2026 incident — wizard-design
// ran 230 sends over 20 days before being flagged). This scanner replays
// the last N hours of exim_mainlog through the same rule, so on CSM
// startup any in-progress or recent compromise is surfaced immediately.
//
// Runs once at daemon startup. Not part of the tiered-check registry
// because it is purely an event-log replay; the realtime watcher owns
// live state thereafter.

// cloudRelayScanPathDefault is where cPanel exim writes its mainlog.
const cloudRelayScanPathDefault = "/var/log/exim_mainlog"

// CloudRelayScanPath is the log file path scanned at startup. Exported
// via var (not const) for tests.
var CloudRelayScanPath = cloudRelayScanPathDefault

// ScanEximHistoryForCloudRelay replays the tail of exim_mainlog for the
// last `lookback` duration and returns a finding per mailbox that
// exceeds the cloud-relay thresholds. Safe to call from goroutines.
//
// The scanner respects the EmailProtection.HighVolumeSenders allowlist,
// mirrors the realtime detector's thresholds exactly, and uses a
// per-user persistent marker in the global store to avoid re-emitting
// the same finding on successive restarts.
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
	byUser := make(map[string][]cloudRelayScanEvent)

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
		events := byUser[user]
		sort.Slice(events, func(i, j int) bool { return events[i].at.Before(events[j].at) })

		maxSends, maxDistinctIPs, fireAt, peakPTR := maxCloudRelayBurst(events)
		multiIP := maxSends >= cloudRelayMinEvents && maxDistinctIPs >= cloudRelayMinDistinctIP
		volume := maxSends >= cloudRelayHighVolumeEvents
		if !multiIP && !volume {
			continue
		}

		// Persistent dedup: skip if we've already fired for this user
		// and no new event has landed since then.
		latestEvent := events[len(events)-1].at
		if alreadyReportedRetro(user, latestEvent) {
			continue
		}

		// Build the IP list (distinct, newest-first).
		seen := make(map[string]struct{}, len(events))
		var ips []string
		for i := len(events) - 1; i >= 0; i-- {
			ip := events[i].ip
			if _, dup := seen[ip]; dup {
				continue
			}
			seen[ip] = struct{}{}
			ips = append(ips, ip)
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
			len(events),
			maxSends, maxDistinctIPs, fireAt.Format("2006-01-02 15:04:05"),
			peakPTR,
			strings.Join(truncateIPList(ips, 10), ", "),
		)

		findings = append(findings, alert.Finding{
			Severity:  alert.Critical,
			Check:     "email_cloud_relay_abuse",
			Message:   msg,
			Details:   truncateDaemon(details, 900),
			Timestamp: now,
		})

		markReportedRetro(user, latestEvent)
	}

	return findings
}

// processCloudRelayScanLine parses a single exim log line and, if it is
// an authenticated cloud-PTR acceptance within the lookback window,
// records it under the AUTH user in `byUser`.
func processCloudRelayScanLine(line string, cfg *config.Config, since time.Time, byUser map[string][]cloudRelayScanEvent) {
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
	ptr := extractEximHostname(line)
	if !isCloudProviderPTR(ptr) {
		return
	}
	ip := extractBracketedIP(line)
	if ip == "" {
		return
	}
	byUser[user] = append(byUser[user], cloudRelayScanEvent{at: ts, ip: ip, ptr: ptr})
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
	for i := range events {
		ips := make(map[string]struct{})
		sends := 0
		lastIdx := i
		for j := i; j < len(events); j++ {
			if events[j].at.Sub(events[i].at) > cloudRelayWindow_ {
				break
			}
			ips[events[j].ip] = struct{}{}
			sends++
			lastIdx = j
		}
		// "Best" = highest send count; tie-break by distinct IPs.
		if sends > bestSends || (sends == bestSends && len(ips) > bestDistinct) {
			bestSends = sends
			bestDistinct = len(ips)
			bestAt = events[lastIdx].at
			bestPTR = events[lastIdx].ptr
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
