package checks

import (
	"bytes"
	"encoding/json"
	"hash/fnv"
	"io"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/metrics"
	"github.com/pidginhost/csm/internal/state"
)

const (
	maxCatchUpBytes  = 8 << 20
	maxTrackedIPs    = 4096
	fingerprintBytes = 512
)

// followState is the persisted position+identity of the syslog follower.
// Populated by readNewSyslogLines (Task 2).
type followState struct {
	Offset    int64  `json:"offset"`
	HeadLen   int    `json:"head_len"`
	HeadFP    string `json:"head_fp"`
	AnchorLen int    `json:"anchor_len"`
	AnchorFP  string `json:"anchor_fp"`
}

// ftpFailTracker is the persisted detector state: where we last read to, and a
// per-IP sliding window of pure-ftpd auth-failure counts bucketed by minute.
type ftpFailTracker struct {
	Follow  followState              `json:"follow"`
	Buckets map[string]map[int64]int `json:"buckets"`
}

func newFTPFailTracker() *ftpFailTracker {
	return &ftpFailTracker{Buckets: map[string]map[int64]int{}}
}

func (t *ftpFailTracker) record(ip string, at time.Time) {
	if t.Buckets == nil {
		t.Buckets = map[string]map[int64]int{}
	}
	m := t.Buckets[ip]
	if m == nil {
		m = map[int64]int{}
		t.Buckets[ip] = m
	}
	m[at.Unix()/60]++
}

// evict drops minute buckets older than windowMin minutes and any IP left empty.
func (t *ftpFailTracker) evict(now time.Time, windowMin int) {
	cutoff := now.Unix()/60 - int64(windowMin)
	for ip, m := range t.Buckets {
		for minute := range m {
			if minute < cutoff {
				delete(m, minute)
			}
		}
		if len(m) == 0 {
			delete(t.Buckets, ip)
		}
	}
}

// capIPs bounds the tracked-IP set, evicting the IPs whose most-recent activity
// is oldest first (ties broken by IP string for deterministic tests).
func (t *ftpFailTracker) capIPs(max int) {
	if len(t.Buckets) <= max {
		return
	}
	type ipAge struct {
		ip     string
		recent int64
	}
	ages := make([]ipAge, 0, len(t.Buckets))
	for ip, m := range t.Buckets {
		var recent int64
		for minute := range m {
			if minute > recent {
				recent = minute
			}
		}
		ages = append(ages, ipAge{ip, recent})
	}
	sort.Slice(ages, func(i, j int) bool {
		if ages[i].recent != ages[j].recent {
			return ages[i].recent < ages[j].recent
		}
		return ages[i].ip < ages[j].ip
	})
	for i := 0; i < len(ages)-max; i++ {
		delete(t.Buckets, ages[i].ip)
	}
}

type ftpOffender struct {
	IP    string
	Count int
}

// offenders returns IPs whose summed failure count over the retained buckets is
// at least threshold, sorted by IP for stable output.
func (t *ftpFailTracker) offenders(threshold int) []ftpOffender {
	var out []ftpOffender
	for ip, m := range t.Buckets {
		sum := 0
		for _, c := range m {
			sum += c
		}
		if sum >= threshold {
			out = append(out, ftpOffender{ip, sum})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// fpAt returns the fnv64a fingerprint (hex) of n bytes at offset off.
// n <= 0 returns "".
func fpAt(f *os.File, off, n int64) (string, error) {
	if n <= 0 {
		return "", nil
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return "", err
	}
	h := fnv.New64a()
	_, _ = h.Write(buf)
	return strconv.FormatUint(h.Sum64(), 16), nil
}

// nextNewline returns the byte offset just after the first '\n' at or after
// from, or size if none is found before size.
func nextNewline(f *os.File, from, size int64) (int64, error) {
	buf := make([]byte, 1)
	for pos := from; pos < size; pos++ {
		if _, err := f.ReadAt(buf, pos); err != nil && err != io.EOF {
			return 0, err
		}
		if buf[0] == '\n' {
			return pos + 1, nil
		}
	}
	return size, nil
}

// completeLines splits data into complete newline-terminated lines and returns
// the number of bytes consumed (through the last '\n'). Trailing partial bytes
// are not returned and not consumed.
func completeLines(data []byte) ([]string, int64) {
	lastNL := bytes.LastIndexByte(data, '\n')
	if lastNL < 0 {
		return nil, 0
	}
	var lines []string
	for _, ln := range bytes.Split(data[:lastNL+1], []byte{'\n'}) {
		if len(ln) == 0 {
			continue
		}
		lines = append(lines, string(ln))
	}
	return lines, int64(lastNL + 1)
}

// chooseStart returns the byte offset to begin reading from, plus skipped bytes
// for first-run catch-up. It restarts at 0 on truncate / rotate / anchor
// mismatch, and follows from st.Offset on a verified append.
func chooseStart(f *os.File, st followState, curSize int64) (int64, int64, error) {
	zero := st.Offset == 0 && st.HeadLen == 0 && st.HeadFP == "" && st.AnchorLen == 0 && st.AnchorFP == ""
	if zero {
		start := curSize - maxCatchUpBytes
		if start <= 0 {
			return 0, 0, nil
		}
		aligned, err := nextNewline(f, start, curSize)
		if err != nil {
			return 0, 0, err
		}
		return aligned, aligned, nil // skipped == bytes before aligned
	}
	if curSize < st.Offset || curSize < int64(st.HeadLen) {
		return 0, 0, nil // truncation / copytruncate
	}
	if st.HeadLen > 0 {
		fp, err := fpAt(f, 0, int64(st.HeadLen))
		if err != nil {
			return 0, 0, err
		}
		if fp != st.HeadFP {
			return 0, 0, nil // different-head rotate
		}
	}
	if st.Offset > 0 && (st.AnchorLen == 0 || st.AnchorFP == "") {
		return 0, 0, nil // incomplete stored anchor
	}
	if st.Offset > 0 {
		fp, err := fpAt(f, st.Offset-int64(st.AnchorLen), int64(st.AnchorLen))
		if err != nil {
			return 0, 0, err
		}
		if fp != st.AnchorFP {
			return 0, 0, nil // same-head replacement
		}
	}
	return st.Offset, 0, nil
}

// fillIdentity sets next's head and anchor fingerprints from the file content.
func fillIdentity(f *os.File, st *followState, curSize int64) error {
	headLen := int64(fingerprintBytes)
	if curSize < headLen {
		headLen = curSize
	}
	hfp, err := fpAt(f, 0, headLen)
	if err != nil {
		return err
	}
	st.HeadLen = int(headLen)
	st.HeadFP = hfp

	anchorLen := int64(fingerprintBytes)
	if st.Offset < anchorLen {
		anchorLen = st.Offset
	}
	afp, err := fpAt(f, st.Offset-anchorLen, anchorLen)
	if err != nil {
		return err
	}
	st.AnchorLen = int(anchorLen)
	st.AnchorFP = afp
	return nil
}

// readNewSyslogLines reads complete lines appended to path since st, returning
// the new lines, the next follow state, bytes skipped by the catch-up cap, and
// any I/O error. On error, next == st so the caller leaves stored state intact.
func readNewSyslogLines(path string, st followState) ([]string, followState, int64, error) {
	f, err := osFS.Open(path)
	if err != nil {
		return nil, st, 0, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, st, 0, err
	}
	curSize := info.Size()

	start, skipped, err := chooseStart(f, st, curSize)
	if err != nil {
		return nil, st, 0, err
	}

	if curSize-start > maxCatchUpBytes {
		capped := curSize - maxCatchUpBytes
		aligned, aerr := nextNewline(f, capped, curSize)
		if aerr != nil {
			return nil, st, 0, aerr
		}
		skipped += aligned - start
		start = aligned
	}

	var lines []string
	var consumed int64
	if curSize-start > 0 {
		data := make([]byte, curSize-start)
		if _, rerr := f.ReadAt(data, start); rerr != nil && rerr != io.EOF {
			return nil, st, 0, rerr
		}
		lines, consumed = completeLines(data)
	}

	next := followState{Offset: start + consumed}
	if err := fillIdentity(f, &next, curSize); err != nil {
		return nil, st, 0, err
	}
	return lines, next, skipped, nil
}

// ftpTrackerKey is underscore-prefixed so state.Store.Update does not prune it
// as a stale non-finding key after 24h.
const ftpTrackerKey = "_ftp_fail_tracker"

func loadFTPFailTracker(store *state.Store) *ftpFailTracker {
	raw, ok := store.GetRaw(ftpTrackerKey)
	if !ok || raw == "" {
		return newFTPFailTracker()
	}
	var decoded ftpFailTracker
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return newFTPFailTracker()
	}
	if invalidFollowState(decoded.Follow) {
		return newFTPFailTracker()
	}
	if decoded.Buckets == nil {
		decoded.Buckets = map[string]map[int64]int{}
	}
	return &decoded
}

// invalidFollowState reports stored follow state that claims an offset but is
// missing the head/anchor identity needed to verify it; such state is dropped
// so the reader falls back to a bounded first-run catch-up.
func invalidFollowState(st followState) bool {
	if st.Offset <= 0 {
		return false
	}
	return st.HeadLen <= 0 || st.HeadFP == "" || st.AnchorLen <= 0 || st.AnchorFP == ""
}

func (t *ftpFailTracker) save(store *state.Store) {
	b, err := json.Marshal(t)
	if err != nil {
		return
	}
	store.SetRaw(ftpTrackerKey, string(b))
}

const ftpSyslogPath = "/var/log/messages"

// effectiveFTPFailWindowMin returns the operator-configured sliding-window
// length in minutes, or the built-in default (30) when unset.
func effectiveFTPFailWindowMin(cfg *config.Config) int {
	if cfg == nil || cfg.Thresholds.FTPFailWindowMin <= 0 {
		return 30
	}
	return cfg.Thresholds.FTPFailWindowMin
}

var (
	ftpSkippedBytes     *metrics.Counter
	ftpSkippedBytesOnce sync.Once
)

func observeFTPSkippedBytes(n int64) {
	ftpSkippedBytesOnce.Do(func() {
		ftpSkippedBytes = metrics.NewCounter(
			"csm_checks_ftp_syslog_skipped_bytes_total",
			"Bytes of /var/log/messages skipped by the FTP detector catch-up cap (8 MiB). Steady growth means the detector is falling behind the syslog write rate or the log has large bursts between cycles.",
		)
		metrics.MustRegister("csm_checks_ftp_syslog_skipped_bytes_total", ftpSkippedBytes)
	})
	ftpSkippedBytes.Add(float64(n))
}
