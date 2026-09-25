package checks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"os"
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
	// wpLoopbackProbeBytes is how much of the log one binary-search probe reads.
	wpLoopbackProbeBytes = 16 * 1024
	// wpLoopbackMaxLineBytes bounds one log line; longer lines are skipped.
	wpLoopbackMaxLineBytes = 64 * 1024
	wpLoopbackMaxTargetLen = 256
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
	windowStart := now.Truncate(time.Hour).Add(-wpLoopbackHours * time.Hour)
	paths := discoverFreshDomlogs(ctx, math.MaxInt, now.Sub(windowStart))
	return scanWPLoopbackLogs(ctx, paths, now)
}

// scanWPLoopbackLogs evaluates the last wpLoopbackHours complete hours before
// now in each log. The hour in progress is left out: it is incomplete.
func scanWPLoopbackLogs(ctx context.Context, paths []string, now time.Time) []alert.Finding {
	end := now.Truncate(time.Hour)
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
	sort.Slice(findings, func(i, j int) bool { return findings[i].Message < findings[j].Message })
	return findings
}

func wpLoopbackSustained(s *wpLoopbackSeries) bool {
	for _, n := range s.perHour {
		if n <= wpLoopbackMaxPerHour {
			return false
		}
	}
	return true
}

func newWPLoopbackFinding(domain, target string, s *wpLoopbackSeries, now time.Time) alert.Finding {
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
		Message:   fmt.Sprintf("Sustained WordPress loopback requests on %s: POST %s", domain, target),
		Details:   details,
		DedupKey:  domain + " " + target,
		Timestamp: now,
	}
}

// readWPLoopbacks counts, per job, the WordPress self-requests stamped in
// [start, end). Only lines that can be one are parsed.
func readWPLoopbacks(ctx context.Context, path string, start, end time.Time) map[string]*wpLoopbackSeries {
	f, err := osFS.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	// The seek can land inside a line. Its tail belongs to a line written
	// before the window, so the time filter drops it like any older line.
	offset := seekDomlogTo(f, info.Size(), start)
	reader := bufio.NewReaderSize(io.NewSectionReader(f, offset, info.Size()-offset), 64*1024)

	series := make(map[string]*wpLoopbackSeries)
	for lines := 0; ; lines++ {
		if lines%4096 == 0 && ctx.Err() != nil {
			return nil
		}
		line, err := readDomlogLine(reader)
		if line != nil && bytes.Contains(line, []byte(`"WordPress/`)) && bytes.Contains(line, []byte(`"POST `)) {
			countWPLoopback(series, string(line), start, end)
		}
		if err != nil {
			return series
		}
	}
}

func countWPLoopback(series map[string]*wpLoopbackSeries, line string, start, end time.Time) {
	rec, ok := parseAccessLogRecord(line)
	if !ok || rec.Method != "POST" || !strings.HasPrefix(rec.UserAgent, "WordPress/") {
		return
	}
	if rec.Time.Before(start) || !rec.Time.Before(end) || !wpLoopbackFromHost(rec.RemoteIP) {
		return
	}
	target := wpLoopbackTarget(rec.URI)
	s := series[target]
	if s == nil {
		s = &wpLoopbackSeries{ua: rec.UserAgent}
		series[target] = s
	}
	s.perHour[int(rec.Time.Sub(start)/time.Hour)]++
	if rec.Status >= 500 {
		s.serverKO++
	}
}

// wpLoopbackTarget names the job a self-request runs: the path, plus the
// admin-ajax action when there is one. Nonces and other per-request values are
// dropped so every run of one job counts together; the path is kept as logged
// because security plugins rename admin-ajax.php. Any tenant's PHP can post to
// any site from this server, so the action is not percent-decoded and the
// result is made safe to display.
func wpLoopbackTarget(uri string) string {
	path, query, _ := strings.Cut(uri, "?")
	target := path
	for _, param := range strings.Split(query, "&") {
		if action, ok := strings.CutPrefix(param, "action="); ok && action != "" {
			target = path + "?action=" + action
			break
		}
	}
	return sanitizeJSTaintDisplay(target, wpLoopbackMaxTargetLen)
}

// seekDomlogTo returns an offset at or before the first line written at or
// after cutoff, found by binary search so a large log is not read from the
// top. A line carries its request's start time but is written when the request
// finishes, so a slow request's stamp runs behind its position in the file.
// Each probe therefore takes the latest stamp in a whole chunk, the one
// closest to when the chunk was written; a single line could be far older and
// send the search past the window.
func seekDomlogTo(f *os.File, size int64, cutoff time.Time) int64 {
	buf := make([]byte, wpLoopbackProbeBytes)
	lo, hi := int64(0), size
	for hi-lo > wpLoopbackProbeBytes {
		mid := lo + (hi-lo)/2
		written, ok := latestStampAt(f, mid, buf)
		if !ok || !written.Before(cutoff) {
			// Unknown or not yet old enough: search earlier. Starting early
			// only costs extra reading; the caller filters every line.
			hi = mid
			continue
		}
		lo = mid
	}
	return lo
}

// latestStampAt returns the latest timestamp among the complete lines in the
// chunk at offset.
func latestStampAt(f *os.File, offset int64, buf []byte) (time.Time, bool) {
	n, err := f.ReadAt(buf, offset)
	if n == 0 && err != nil {
		return time.Time{}, false
	}
	chunk := buf[:n]
	first := bytes.IndexByte(chunk, '\n')
	if first < 0 {
		return time.Time{}, false
	}
	chunk = chunk[first+1:]
	var latest time.Time
	for {
		nl := bytes.IndexByte(chunk, '\n')
		if nl < 0 {
			break
		}
		if rec, ok := parseAccessLogRecord(string(chunk[:nl])); ok && rec.Time.After(latest) {
			latest = rec.Time
		}
		chunk = chunk[nl+1:]
	}
	return latest, !latest.IsZero()
}

// readDomlogLine returns the next line without its newline. A line over
// wpLoopbackMaxLineBytes is consumed and returned as nil.
func readDomlogLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	tooLong := false
	for {
		chunk, err := r.ReadSlice('\n')
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
