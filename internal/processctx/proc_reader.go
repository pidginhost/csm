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
	return e, nil
}

// readFileWithDeadline reads up to 4 KiB from path; returns (data, true) on
// success or (nil, false) on any error or deadline expiry. /proc files are
// small; using ReadFile keeps the normal path simple. The generic deadline
// helper is tested with an injected slow function instead of a FIFO because
// general filesystem opens cannot be cancelled safely on every platform.
func readFileWithDeadline(path string, d time.Duration) ([]byte, bool) {
	return runBytesWithDeadline(d, func() ([]byte, error) {
		data, err := os.ReadFile(path)
		if len(data) > 4096 {
			data = data[:4096]
		}
		return data, err
	})
}

func runBytesWithDeadline(d time.Duration, fn func() ([]byte, error)) ([]byte, bool) {
	if d <= 0 {
		data, err := fn()
		return data, err == nil
	}
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
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
	type result struct {
		target string
		err    error
	}
	ch := make(chan result, 1)
	go func() {
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
