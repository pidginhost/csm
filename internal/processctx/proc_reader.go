package processctx

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ErrProcessGone is returned by ProcReader.Read when the /proc/<pid> tree
// no longer exists. Callers must treat this as a soft miss, not an error
// finding - short-lived processes are expected.
var ErrProcessGone = errors.New("process gone")

// ProcReader reads /proc/<pid>/{status,cmdline,exe} with a per-file deadline.
type ProcReader struct {
	root            string
	perFileDeadline time.Duration
}

// NewProcReader constructs a reader rooted at procRoot ("/proc" in production,
// a temp dir in tests). perFileDeadline bounds each individual file read.
func NewProcReader(procRoot string, perFileDeadline time.Duration) *ProcReader {
	return &ProcReader{root: procRoot, perFileDeadline: perFileDeadline}
}

// Read returns a processEntry populated from /proc/<pid>. Fields that cannot
// be read within the deadline are left at their zero value; the caller still
// gets an entry with whatever was retrievable. Returns ErrProcessGone when
// the /proc/<pid> directory does not exist.
func (r *ProcReader) Read(pid int) (processEntry, error) {
	dir := filepath.Join(r.root, strconv.Itoa(pid))
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return processEntry{}, ErrProcessGone
		}
		return processEntry{}, err
	}
	e := processEntry{PID: pid, ProcRead: true}

	if data, ok := readFileWithDeadline(filepath.Join(dir, "status"), r.perFileDeadline); ok {
		e.PPID = parseStatusPPID(string(data))
		e.UID, e.UIDKnown = parseStatusUIDKnown(string(data))
		e.Comm = parseStatusName(string(data))
	}
	if data, ok := readFileWithDeadline(filepath.Join(dir, "cmdline"), r.perFileDeadline); ok {
		e.Cmdline = parseCmdline(data)
	}
	if target, ok := readlinkWithDeadline(filepath.Join(dir, "exe"), r.perFileDeadline); ok {
		e.Exe = target
	}
	if data, ok := readFileWithDeadline(filepath.Join(dir, "stat"), r.perFileDeadline); ok {
		if t, ok := r.parseStartedAt(data); ok {
			e.StartedAt = t
		}
	}
	return e, nil
}

// ReadStartedAt returns only /proc/<pid>/stat's process start time. It lets
// detector hot paths capture a lightweight PID-reuse token without reading
// status, cmdline, exe, or identity data.
func (r *ProcReader) ReadStartedAt(pid int) (time.Time, bool) {
	if pid <= 0 {
		return time.Time{}, false
	}
	path := filepath.Join(r.root, strconv.Itoa(pid), "stat")
	data, ok := readFileWithDeadline(path, r.perFileDeadline)
	if !ok {
		return time.Time{}, false
	}
	return r.parseStartedAt(data)
}

// procStatStartTime extracts field 22 of /proc/<pid>/stat (starttime in
// clock ticks since boot). Field positions are deterministic except
// that the second field (comm) is parenthesized and may contain
// arbitrary bytes including spaces -- so we anchor on the final ")"
// before splitting the rest.
func procStatStartTime(data []byte) (int64, bool) {
	end := bytes.LastIndexByte(data, ')')
	if end < 0 || end+1 >= len(data) {
		return 0, false
	}
	rest := strings.TrimSpace(string(data[end+1:]))
	fields := strings.Fields(rest)
	// rest starts at field 3 (state); starttime is field 22, i.e. index 19 in rest.
	const starttimeIdx = 19
	if len(fields) <= starttimeIdx {
		return 0, false
	}
	v, err := strconv.ParseInt(fields[starttimeIdx], 10, 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}

// parseStartedAt converts /proc/<pid>/stat's starttime field into an
// absolute time using the host's boot time. Returns (zero, false) on
// any parse or btime resolution failure so callers leave the field
// unset rather than emitting bogus timestamps.
func (r *ProcReader) parseStartedAt(stat []byte) (time.Time, bool) {
	ticks, ok := procStatStartTime(stat)
	if !ok {
		return time.Time{}, false
	}
	boot, ok := r.bootTime()
	if !ok {
		return time.Time{}, false
	}
	hz := clockTicksPerSecond()
	if hz <= 0 {
		return time.Time{}, false
	}
	sec := ticks / hz
	rem := ticks % hz
	ns := rem * int64(time.Second) / hz
	return boot.Add(time.Duration(sec)*time.Second + time.Duration(ns)), true
}

// readFileWithDeadline reads up to 4 KiB from path; returns (data, true) on
// success or (nil, false) on any error or deadline expiry. /proc files are
// small; using ReadFile keeps the normal path simple. The generic deadline
// helper is tested with an injected slow function instead of a FIFO because
// general filesystem opens cannot be cancelled safely on every platform.
func readFileWithDeadline(path string, d time.Duration) ([]byte, bool) {
	return runBytesWithDeadline(d, func() ([]byte, error) {
		// #nosec G304 -- path is constructed from ProcReader.root + numeric PID;
		// callers only pass procfs entries under r.root.
		data, err := os.ReadFile(path)
		if len(data) > 4096 {
			data = data[:4096]
		}
		return data, err
	})
}

// procReadConcurrency bounds how many deadline-bound /proc reads run at once.
// A blocking syscall goroutine cannot be cancelled in Go, so a wedged /proc
// entry (NFS-backed, D-state) leaks its goroutine until the kernel returns --
// which may be never. The cap turns what was an unbounded leak under PID-reuse
// churn into a fixed ceiling: once it is reached, further reads fail fast
// instead of spawning more abandonable goroutines. A goroutine releases its
// slot only when its syscall finally returns, so genuinely-stuck reads keep
// their slot (correctly counting against the ceiling).
const procReadConcurrency = 64

var procReadSem = make(chan struct{}, procReadConcurrency)

func acquireProcReadSlot() bool {
	select {
	case procReadSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseProcReadSlot() { <-procReadSem }

func runBytesWithDeadline(d time.Duration, fn func() ([]byte, error)) ([]byte, bool) {
	if d <= 0 {
		data, err := fn()
		return data, err == nil
	}
	if !acquireProcReadSlot() {
		return nil, false
	}
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		defer releaseProcReadSlot()
		data, err := fn()
		ch <- result{data: data, err: err}
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case res := <-ch:
		if res.err != nil {
			return nil, false
		}
		return res.data, true
	case <-timer.C:
		return nil, false
	}
}

// readlinkWithDeadline runs Readlink in a goroutine and gives up after d.
func readlinkWithDeadline(path string, d time.Duration) (string, bool) {
	if !acquireProcReadSlot() {
		return "", false
	}
	type result struct {
		target string
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		defer releaseProcReadSlot()
		t, err := os.Readlink(path)
		ch <- result{t, err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			return "", false
		}
		return res.target, true
	case <-time.After(d):
		return "", false
	}
}

func parseStatusName(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if rest, ok := strings.CutPrefix(line, "Name:\t"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

func parseStatusPPID(s string) int {
	for _, line := range strings.Split(s, "\n") {
		if rest, ok := strings.CutPrefix(line, "PPid:\t"); ok {
			v, _ := strconv.Atoi(strings.TrimSpace(rest))
			return v
		}
	}
	return 0
}

func parseStatusUID(s string) int {
	uid, _ := parseStatusUIDKnown(s)
	return uid
}

func parseStatusUIDKnown(s string) (int, bool) {
	for _, line := range strings.Split(s, "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:\t"); ok {
			fields := strings.Fields(rest)
			if len(fields) == 0 {
				return 0, false
			}
			v, err := strconv.Atoi(fields[0])
			return v, err == nil
		}
	}
	return 0, false
}

func parseCmdline(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	parts := bytes.Split(b, []byte{0})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		out = append(out, string(p))
	}
	if len(out) == 0 {
		return nil
	}
	return sanitizeCmdline(out)
}

const maxCmdlineArgLen = 256

var sensitiveCmdlineKeys = []string{"password", "passwd", "secret", "token", "api_key", "apikey"}

func sanitizeCmdline(args []string) []string {
	out := make([]string, 0, len(args))
	redactNext := false
	for _, arg := range args {
		if redactNext {
			out = append(out, "<redacted>")
			redactNext = false
			continue
		}
		lower := strings.ToLower(arg)
		redacted := false
		for _, key := range sensitiveCmdlineKeys {
			if strings.Contains(lower, key+"=") {
				prefix, _, _ := strings.Cut(arg, "=")
				out = append(out, truncateCmdlineArg(prefix+"=<redacted>"))
				redacted = true
				break
			}
			if lower == "--"+key || lower == "-"+key {
				out = append(out, truncateCmdlineArg(arg))
				redactNext = true
				redacted = true
				break
			}
		}
		if redacted {
			continue
		}
		out = append(out, truncateCmdlineArg(arg))
	}
	return out
}

func truncateCmdlineArg(arg string) string {
	if len(arg) <= maxCmdlineArgLen {
		return arg
	}
	return arg[:maxCmdlineArgLen]
}
