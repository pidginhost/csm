package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// wpLoopbackStateKey is underscore-prefixed so state.Store.Update does not
// prune it as a stale non-finding key.
const wpLoopbackStateKey = "_perf_wp_loopback"

// wpLoopbackJob counts one job's self-requests by local clock hour. Hours maps
// the hour's start (Unix seconds) to its request and 5xx counts. Target and UA
// are display forms; the job's identity is the hash of its full target.
type wpLoopbackJob struct {
	Target string           `json:"target"`
	UA     string           `json:"ua"`
	Hours  map[int64][2]int `json:"hours"`
}

// wpLoopbackLog is one vhost log's read position and the jobs seen in it
// within the window.
type wpLoopbackLog struct {
	Follow followState               `json:"follow"`
	Jobs   map[string]*wpLoopbackJob `json:"jobs,omitempty"`
}

// wpLoopbackState is keyed by log path.
type wpLoopbackState map[string]*wpLoopbackLog

// CheckWPLoopbackRequests follows every active vhost log for WordPress sites
// calling themselves faster than WordPress's own schedulers ever do, hour
// after hour. Each run reads only what the logs gained since the last one and
// keeps hourly counts in the scan state. The runner enforces a 60-minute
// throttle via checkThrottleMin.
func CheckWPLoopbackRequests(ctx context.Context, cfg *config.Config, scanState *state.Store) []alert.Finding {
	if !perfEnabled(cfg) {
		return nil
	}
	now := wpLoopbackNow()
	windowStart := wpLoopbackWindowEnd(now).Add(-wpLoopbackHours * time.Hour)
	discoveryFailed := false
	paths := discoverFreshDomlogsWithErrors(ctx, math.MaxInt, now.Sub(windowStart), func(err error) {
		discoveryFailed = true
		markScanReadError(ctx, "perf_wp_loopback", err)
	})
	previous := loadWPLoopbackState(scanState)
	findings, next := scanWPLoopbackLogsState(ctx, paths, now, previous)
	if ctx.Err() != nil {
		return nil
	}
	if discoveryFailed {
		// Logs discovery could not list were not read, not gone.
		for path, log := range previous {
			if _, ok := next[path]; !ok {
				next[path] = log
			}
		}
	}
	storeWPLoopbackState(scanState, next)
	return findings
}

// scanWPLoopbackLogs evaluates logs with no saved state, reading each whole
// (up to the first-run catch-up limit).
func scanWPLoopbackLogs(ctx context.Context, paths []string, now time.Time) []alert.Finding {
	findings, _ := scanWPLoopbackLogsState(ctx, paths, now, nil)
	return findings
}

// scanWPLoopbackLogsState follows each log from its saved position and judges
// the last wpLoopbackHours complete hours before now; the hour in progress is
// counted for later runs but not judged. It returns the findings and the
// state to save. A log that fails to read keeps its previous state.
func scanWPLoopbackLogsState(ctx context.Context, paths []string, now time.Time, previous wpLoopbackState) ([]alert.Finding, wpLoopbackState) {
	end := wpLoopbackWindowEnd(now)
	start := end.Add(-wpLoopbackHours * time.Hour)
	next := make(wpLoopbackState, len(paths))
	var findings []alert.Finding
	for _, path := range paths {
		if ctx.Err() != nil {
			break
		}
		domain := domainFromDomlogPath(path)
		if domain == "" {
			continue
		}
		log, ok := followWPLoopbackLog(ctx, path, previous[path], start)
		if !ok {
			markCheckIncomplete(ctx, "perf_wp_loopback")
			if old := previous[path]; old != nil {
				next[path] = old
			}
			continue
		}
		next[path] = log
		for key, job := range log.Jobs {
			if counts, serverKO, sustained := wpLoopbackWindowCounts(job, start); sustained {
				findings = append(findings, newWPLoopbackFinding(domain, key, job, counts, serverKO, now))
			}
		}
	}
	if ctx.Err() != nil {
		markCheckIncomplete(ctx, "perf_wp_loopback")
		return nil, previous
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Message == findings[j].Message {
			return findings[i].DedupKey < findings[j].DedupKey
		}
		return findings[i].Message < findings[j].Message
	})
	return findings, next
}

func wpLoopbackWindowEnd(now time.Time) time.Time {
	// Truncate rounds absolute time, which splits local clock hours in zones
	// whose UTC offset includes a half or quarter hour.
	return now.Add(-time.Duration(now.Minute())*time.Minute -
		time.Duration(now.Second())*time.Second - time.Duration(now.Nanosecond()))
}

// wpLoopbackWindowCounts returns the job's requests in each window hour, its
// 5xx answers across them, and whether every hour is over the rate.
func wpLoopbackWindowCounts(job *wpLoopbackJob, start time.Time) (counts [wpLoopbackHours]int, serverKO int, sustained bool) {
	sustained = true
	for i := range counts {
		hour := job.Hours[start.Add(time.Duration(i)*time.Hour).Unix()]
		counts[i], serverKO = hour[0], serverKO+hour[1]
		if counts[i] <= wpLoopbackMaxPerHour {
			sustained = false
		}
	}
	return counts, serverKO, sustained
}

func newWPLoopbackFinding(domain, key string, job *wpLoopbackJob, counts [wpLoopbackHours]int, serverKO int, now time.Time) alert.Finding {
	shown := make([]string, len(counts))
	for i, n := range counts {
		shown[i] = strconv.Itoa(n)
	}
	details := fmt.Sprintf("From this server, %s per hour over the last %d hours", strings.Join(shown, ", "), wpLoopbackHours)
	if serverKO > 0 {
		details += fmt.Sprintf("; %d answered with a 5xx error", serverKO)
	}
	details += ". User-Agent: " + job.UA
	return alert.Finding{
		Severity:  alert.Warning,
		Check:     "perf_wp_loopback",
		Message:   fmt.Sprintf("Sustained WordPress loopback requests on %s: POST %s", domain, job.Target),
		Details:   details,
		DedupKey:  domain + " " + key,
		Timestamp: now,
	}
}

// followWPLoopbackLog reads the complete lines path gained since old and
// returns the updated log state. Requests are stamped when they start but
// logged when they finish, so no part of a log can be skipped by its
// timestamps; following it instead reads every byte once across runs. A
// rotated, truncated or replaced file is read from its start, and a first
// run catches up on at most the tail the shared follower allows. Hours before
// start are dropped. old is never modified.
func followWPLoopbackLog(ctx context.Context, path string, old *wpLoopbackLog, start time.Time) (*wpLoopbackLog, bool) {
	f, err := osFS.Open(path)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, false
	}
	size := info.Size()

	log := &wpLoopbackLog{Jobs: make(map[string]*wpLoopbackJob)}
	var follow followState
	if old != nil {
		follow = old.Follow
		for key, job := range old.Jobs {
			kept := &wpLoopbackJob{Target: job.Target, UA: job.UA, Hours: make(map[int64][2]int, len(job.Hours))}
			for hour, c := range job.Hours {
				if hour >= start.Unix() {
					kept.Hours[hour] = c
				}
			}
			if len(kept.Hours) > 0 {
				log.Jobs[key] = kept
			}
		}
	}
	offset, _, err := chooseStart(f, follow, size)
	if err != nil {
		return nil, false
	}

	// The size snapshot bounds the read against concurrent appends; a file
	// that shrinks while being read ends early and fails the run.
	limited := &io.LimitedReader{R: io.NewSectionReader(f, offset, size-offset), N: size - offset}
	reader := bufio.NewReaderSize(limited, wpLoopbackMaxLineBytes)
	pos := offset
	for {
		line, n, err := readDomlogLine(ctx, reader)
		if err == io.EOF && limited.N == 0 {
			// Anything left is a line still being written; the next run
			// starts at its beginning.
			break
		}
		if err != nil {
			return nil, false
		}
		pos += int64(n)
		if line != nil && bytes.Contains(line, []byte(`"WordPress/`)) && bytes.Contains(line, []byte(`"POST `)) {
			if !countWPLoopback(log.Jobs, string(line), start) {
				return nil, false
			}
		}
	}
	log.Follow = followState{Offset: pos}
	if err := fillIdentity(f, &log.Follow, size); err != nil {
		return nil, false
	}
	return log, true
}

func countWPLoopback(jobs map[string]*wpLoopbackJob, line string, start time.Time) bool {
	rec, ok := parseAccessLogRecordWithURILimit(line, wpLoopbackMaxLineBytes)
	if !ok || rec.Method != "POST" || !strings.HasPrefix(rec.UserAgent, "WordPress/") {
		return true
	}
	if rec.Time.Before(start) || !wpLoopbackFromHost(rec.RemoteIP) {
		return true
	}
	target := wpLoopbackTarget(rec.URI)
	sum := sha256.Sum256([]byte(target))
	key := hex.EncodeToString(sum[:])
	job := jobs[key]
	if job == nil {
		if len(jobs) >= wpLoopbackMaxSeries {
			return false
		}
		// Copy bounded display fields so short substrings do not retain the
		// entire input line, including discarded query values and headers.
		job = &wpLoopbackJob{
			Target: strings.Clone(sanitizeJSTaintDisplay(target, wpLoopbackMaxTargetLen)),
			UA:     strings.Clone(sanitizeJSTaintDisplay(rec.UserAgent, 512)),
			Hours:  make(map[int64][2]int),
		}
		jobs[key] = job
	}
	hour := wpLoopbackWindowEnd(rec.Time).Unix()
	c := job.Hours[hour]
	c[0]++
	if rec.Status >= 500 && rec.Status < 600 {
		c[1]++
	}
	job.Hours[hour] = c
	return true
}

func loadWPLoopbackState(scanState *state.Store) wpLoopbackState {
	if scanState == nil {
		return nil
	}
	raw, ok := scanState.GetRaw(wpLoopbackStateKey)
	if !ok {
		return nil
	}
	var st wpLoopbackState
	if json.Unmarshal([]byte(raw), &st) != nil {
		return nil
	}
	return st
}

func storeWPLoopbackState(scanState *state.Store, st wpLoopbackState) {
	if scanState == nil {
		return
	}
	if len(st) == 0 {
		if err := scanState.DeleteRawAndSave(wpLoopbackStateKey); err != nil {
			fmt.Fprintf(os.Stderr, "perf_wp_loopback: state clear: %v\n", err)
		}
		return
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return
	}
	if err := scanState.SetRawAndSave(wpLoopbackStateKey, string(raw)); err != nil {
		fmt.Fprintf(os.Stderr, "perf_wp_loopback: state write: %v\n", err)
	}
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

// readDomlogLine returns the next line without its newline and the bytes it
// consumed, newline included. A line over wpLoopbackMaxLineBytes is consumed
// and returned as nil. At the end of input, a final line with no newline is
// returned with io.EOF.
func readDomlogLine(ctx context.Context, r *bufio.Reader) ([]byte, int, error) {
	var line []byte
	consumed := 0
	tooLong := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, consumed, err
		}
		chunk, err := r.ReadSlice('\n')
		consumed += len(chunk)
		if line == nil && !tooLong && err != bufio.ErrBufferFull && len(chunk) <= wpLoopbackMaxLineBytes {
			return bytes.TrimRight(chunk, "\r\n"), consumed, err
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
			return nil, consumed, err
		}
		return bytes.TrimRight(line, "\r\n"), consumed, err
	}
}
