package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/netutil"
	"github.com/pidginhost/csm/internal/state"
)

const (
	// wpLoopbackMaxPerHour is the most self-requests one job makes in an hour
	// under WordPress's own schedulers: the cron spawn and Action Scheduler's
	// admin dispatch each hold a 60-second lock. A job over it every hour is
	// either re-triggered by page views or re-dispatching a queue that does
	// not drain.
	wpLoopbackMaxPerHour = 60
	// wpLoopbackHours is how many consecutive complete hours must each be over
	// the rate. A bulk import or a one-off backlog stops well before this.
	wpLoopbackHours = 3
	// wpLoopbackMaxLineBytes bounds one log line; longer lines are skipped.
	wpLoopbackMaxLineBytes = 64 * 1024
	wpLoopbackMaxTargetLen = 256
	// Job names are tenant-controlled. Bound aggregate memory independently
	// of log size and preserve prior findings when coverage exceeds this cap.
	wpLoopbackMaxSeries = 4096
)

var wpLoopbackNow = time.Now

// wpLoopbackFromHost reports whether a request came from this server: its
// loopback interface or one of its own addresses, which is how cPanel sites
// usually reach themselves.
var wpLoopbackFromHost = func(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && (parsed.IsLoopback() || netutil.IsHostAddress(ip))
}

type wpLoopbackSeries struct {
	perHour  [wpLoopbackHours]int
	serverKO int
	ua       string
	target   string
}

// CheckWPLoopbackRequests reads the last few hours of every active vhost log
// for WordPress sites calling themselves faster than WordPress's own
// schedulers ever do, hour after hour. The runner enforces a 60-minute
// throttle via checkThrottleMin.
func CheckWPLoopbackRequests(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}
	now := wpLoopbackNow()
	windowStart := wpLoopbackWindowEnd(now).Add(-wpLoopbackHours * time.Hour)
	paths := discoverFreshDomlogsWithErrors(ctx, math.MaxInt, now.Sub(windowStart), func(err error) {
		markScanReadError(ctx, "perf_wp_loopback", err)
	})
	return scanWPLoopbackLogs(ctx, paths, now)
}

// scanWPLoopbackLogs evaluates the last wpLoopbackHours complete hours before
// now in each log. The hour in progress is left out: it is incomplete.
func scanWPLoopbackLogs(ctx context.Context, paths []string, now time.Time) []alert.Finding {
	end := wpLoopbackWindowEnd(now)
	start := end.Add(-wpLoopbackHours * time.Hour)
	var findings []alert.Finding
	for _, path := range paths {
		if ctx.Err() != nil {
			break
		}
		domain := domainFromDomlogPath(path)
		if domain == "" {
			continue
		}
		series := readWPLoopbacks(ctx, path, start, end)
		for target, s := range series {
			if wpLoopbackSustained(s) {
				findings = append(findings, newWPLoopbackFinding(domain, target, s, now))
			}
		}
	}
	if ctx.Err() != nil {
		markCheckIncomplete(ctx, "perf_wp_loopback")
		return nil
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Message == findings[j].Message {
			return findings[i].DedupKey < findings[j].DedupKey
		}
		return findings[i].Message < findings[j].Message
	})
	return findings
}

func wpLoopbackWindowEnd(now time.Time) time.Time {
	// Truncate rounds absolute time, which splits local clock hours in zones
	// whose UTC offset includes a half or quarter hour.
	return now.Add(-time.Duration(now.Minute())*time.Minute -
		time.Duration(now.Second())*time.Second - time.Duration(now.Nanosecond()))
}

func wpLoopbackSustained(s *wpLoopbackSeries) bool {
	for _, n := range s.perHour {
		if n <= wpLoopbackMaxPerHour {
			return false
		}
	}
	return true
}

func newWPLoopbackFinding(domain string, target [sha256.Size]byte, s *wpLoopbackSeries, now time.Time) alert.Finding {
	counts := make([]string, len(s.perHour))
	for i, n := range s.perHour {
		counts[i] = strconv.Itoa(n)
	}
	details := fmt.Sprintf("From this server, %s per hour over the last %d hours", strings.Join(counts, ", "), wpLoopbackHours)
	if s.serverKO > 0 {
		details += fmt.Sprintf("; %d answered with a 5xx error", s.serverKO)
	}
	details += ". User-Agent: " + s.ua
	return alert.Finding{
		Severity:  alert.Warning,
		Check:     "perf_wp_loopback",
		Message:   fmt.Sprintf("Sustained WordPress loopback requests on %s: POST %s", domain, s.target),
		Details:   details,
		DedupKey:  fmt.Sprintf("%s %x", domain, target),
		Timestamp: now,
	}
}

// readWPLoopbacks counts, per job, the WordPress self-requests stamped in
// [start, end). Only lines that can be one are parsed.
func readWPLoopbacks(ctx context.Context, path string, start, end time.Time) map[[sha256.Size]byte]*wpLoopbackSeries {
	f, err := osFS.Open(path)
	if err != nil {
		markCheckIncomplete(ctx, "perf_wp_loopback")
		return nil
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		markCheckIncomplete(ctx, "perf_wp_loopback")
		return nil
	}
	// Requests are stamped at start but logged at completion. Arbitrarily
	// large batches can carry old stamps after in-window lines, so neither
	// binary search nor stopping at an old chunk can exclude a safe prefix.
	// Snapshot the size so concurrent appends cannot extend this scan forever.
	limited := &io.LimitedReader{R: f, N: info.Size()}
	reader := bufio.NewReaderSize(limited, wpLoopbackMaxLineBytes)

	series := make(map[[sha256.Size]byte]*wpLoopbackSeries)
	for {
		line, err := readDomlogLine(ctx, reader)
		if line != nil && bytes.Contains(line, []byte(`"WordPress/`)) && bytes.Contains(line, []byte(`"POST `)) {
			if !countWPLoopback(series, string(line), start, end) {
				markCheckIncomplete(ctx, "perf_wp_loopback")
				return nil
			}
		}
		if err != nil {
			if err != io.EOF || limited.N != 0 {
				markCheckIncomplete(ctx, "perf_wp_loopback")
				return nil
			}
			return series
		}
	}
}

func countWPLoopback(series map[[sha256.Size]byte]*wpLoopbackSeries, line string, start, end time.Time) bool {
	rec, ok := parseAccessLogRecordWithURILimit(line, wpLoopbackMaxLineBytes)
	if !ok || rec.Method != "POST" || !strings.HasPrefix(rec.UserAgent, "WordPress/") {
		return true
	}
	if rec.Time.Before(start) || !rec.Time.Before(end) || !wpLoopbackFromHost(rec.RemoteIP) {
		return true
	}
	target := wpLoopbackTarget(rec.URI)
	key := sha256.Sum256([]byte(target))
	s := series[key]
	if s == nil {
		if len(series) >= wpLoopbackMaxSeries {
			return false
		}
		// Copy bounded display fields so short substrings do not retain the
		// entire input line, including discarded query values and headers.
		s = &wpLoopbackSeries{
			ua:     strings.Clone(sanitizeJSTaintDisplay(rec.UserAgent, 512)),
			target: strings.Clone(sanitizeJSTaintDisplay(target, wpLoopbackMaxTargetLen)),
		}
		series[key] = s
	}
	s.perHour[int(rec.Time.Sub(start)/time.Hour)]++
	if rec.Status >= 500 && rec.Status < 600 {
		s.serverKO++
	}
	return true
}

// wpLoopbackTarget names the job a self-request runs: the path, plus the
// admin-ajax action when there is one. Nonces and other per-request values are
// dropped so every run of one job counts together; the path is kept as logged
// because security plugins rename admin-ajax.php. Keep the logged bytes for
// identity; sanitizing or truncating them would merge different jobs.
func wpLoopbackTarget(uri string) string {
	path, query, _ := strings.Cut(uri, "?")
	target := path
	for _, param := range strings.Split(query, "&") {
		if action, ok := strings.CutPrefix(param, "action="); ok && action != "" {
			target = path + "?action=" + action
			break
		}
	}
	return target
}

// readDomlogLine returns the next line without its newline. A line over
// wpLoopbackMaxLineBytes is consumed and returned as nil.
func readDomlogLine(ctx context.Context, r *bufio.Reader) ([]byte, error) {
	var line []byte
	tooLong := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chunk, err := r.ReadSlice('\n')
		if line == nil && !tooLong && err != bufio.ErrBufferFull && len(chunk) <= wpLoopbackMaxLineBytes {
			return bytes.TrimRight(chunk, "\r\n"), err
		}
		if !tooLong {
			if len(line)+len(chunk) > wpLoopbackMaxLineBytes {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if tooLong {
			return nil, err
		}
		return bytes.TrimRight(line, "\r\n"), err
	}
}
