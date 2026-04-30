package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// afAlgEvent is the parsed view of a single SYSCALL record tagged with the
// csm_af_alg_socket auditd key. Fields are kept as strings because the
// downstream consumer is a human-readable Finding message.
type afAlgEvent struct {
	Timestamp string // e.g. "1761826283.452"
	Serial    string // e.g. "91234"
	UID       string
	AUID      string
	PID       string // process id from the SYSCALL record; needed for live kill reaction
	Comm      string
	Exe       string
}

// AFAlgEvent is the package-public view of afAlgEvent used by callers
// outside internal/checks (the daemon's live audit-log listener emits
// findings derived from this shape).
type AFAlgEvent = afAlgEvent

// ParseAFAlgEventLine is the exported alias of parseAFAlgEvent for the
// daemon's live listener. The unexported form stays internal so the
// rest of this package can refer to the type by its short name.
func ParseAFAlgEventLine(line string) (AFAlgEvent, bool) {
	return parseAFAlgEvent(line)
}

// after reports whether e is strictly newer than other. Comparison is
// (Timestamp, Serial) lexicographic with numeric semantics.
func (e afAlgEvent) after(other afAlgEvent) bool {
	if e.Timestamp != other.Timestamp {
		eFloat, _ := strconv.ParseFloat(e.Timestamp, 64)
		otherFloat, _ := strconv.ParseFloat(other.Timestamp, 64)
		return eFloat > otherFloat
	}
	// Avoid the local name `os` here — it shadows the stdlib package
	// of the same name and would silently break a future edit that
	// adds an `os` import to this file.
	eSerial, _ := strconv.Atoi(e.Serial)
	otherSerial, _ := strconv.Atoi(other.Serial)
	return eSerial > otherSerial
}

// parseAFAlgEvent extracts the relevant fields from a single audit log line.
// It returns (event, true) only when the line is a SYSCALL record carrying
// the csm_af_alg_socket key. Anything else returns ok=false.
func parseAFAlgEvent(line string) (afAlgEvent, bool) {
	if !strings.Contains(line, `key="csm_af_alg_socket"`) {
		return afAlgEvent{}, false
	}

	ts, serial, ok := parseAuditMsgID(line)
	if !ok {
		return afAlgEvent{}, false
	}

	ev := afAlgEvent{Timestamp: ts, Serial: serial}
	ev.UID = extractAuditField(line, "uid")
	ev.AUID = extractAuditField(line, "auid")
	ev.PID = extractAuditField(line, "pid")
	ev.Comm = extractAuditField(line, "comm")
	ev.Exe = extractAuditField(line, "exe")
	return ev, true
}

// parseAuditMsgID extracts (timestamp, serial) from `msg=audit(TS:SERIAL):`.
func parseAuditMsgID(line string) (string, string, bool) {
	const marker = "msg=audit("
	i := strings.Index(line, marker)
	if i < 0 {
		return "", "", false
	}
	rest := line[i+len(marker):]
	end := strings.Index(rest, ")")
	if end < 0 {
		return "", "", false
	}
	inside := rest[:end]
	colon := strings.Index(inside, ":")
	if colon < 0 {
		return "", "", false
	}
	ts := inside[:colon]
	serial := inside[colon+1:]
	if _, err := strconv.ParseFloat(ts, 64); err != nil {
		return "", "", false
	}
	if _, err := strconv.Atoi(serial); err != nil {
		return "", "", false
	}
	return ts, serial, true
}

// extractAuditField returns the value of `key=...` from an audit log line.
// Quoted values may contain spaces; bare values are whitespace-delimited.
func extractAuditField(line, key string) string {
	prefix := key + "="
	idx := 0
	for {
		i := strings.Index(line[idx:], prefix)
		if i < 0 {
			return ""
		}
		i += idx
		// Require start-of-line or preceding whitespace so "auid=" doesn't
		// match when we asked for "uid=".
		if i > 0 && line[i-1] != ' ' && line[i-1] != '\t' {
			idx = i + 1
			continue
		}
		rest := line[i+len(prefix):]
		if strings.HasPrefix(rest, `"`) {
			rest = rest[1:]
			end := strings.Index(rest, `"`)
			if end < 0 {
				return ""
			}
			return rest[:end]
		}
		end := strings.IndexAny(rest, " \t")
		if end < 0 {
			return rest
		}
		return rest[:end]
	}
}

const (
	afAlgLogPath   = "/var/log/audit/audit.log"
	afAlgCursorKey = "_af_alg_last_seen"
)

// CheckAFAlgSocketUsage scans the audit log for csm_af_alg_socket events
// and emits one Critical finding per strictly-newer event. The first run
// alerts on every event found — AF_ALG-from-userland is an exploit signature
// for CVE-2026-31431 ("Copy Fail"), not a baseline metric, so silent seeding
// would hide pre-existing compromise. The cursor in state.Store prevents
// duplicates on subsequent sweeps and survives daemon restarts.
//
// Filtering is delegated to grep so we don't load the whole multi-hundred-MB
// audit log into memory each tick (same precedent as getAuditShadowInfo in
// auth.go). RunAllowNonZero is required because grep returns exit 1 on
// "no match" — the healthy default — and that must not surface as an error.
func CheckAFAlgSocketUsage(_ context.Context, _ *config.Config, st *state.Store) []alert.Finding {
	// RunAllowNonZero swallows every non-zero exit (see runCmdAllowNonZeroReal
	// in helpers.go) — including exit 1 (no match) and exit 2 (audit log not
	// installed). The non-error path is therefore the only one we need to
	// reason about here: empty output means "nothing to do".
	out, err := cmdExec.RunAllowNonZero("grep", "-a", "csm_af_alg_socket", afAlgLogPath)
	if err != nil {
		return nil
	}
	if len(out) == 0 {
		return nil
	}

	cursorRaw, hasCursor := st.GetRaw(afAlgCursorKey)
	cursor := decodeCursor(cursorRaw)

	var findings []alert.Finding
	highest := cursor
	highestSet := hasCursor

	for _, line := range strings.Split(string(out), "\n") {
		ev, ok := parseAFAlgEvent(line)
		if !ok {
			continue
		}
		if hasCursor && !ev.after(cursor) {
			continue
		}
		findings = append(findings, alert.Finding{
			Severity: alert.Critical,
			Check:    "af_alg_socket_use",
			Message:  fmt.Sprintf("AF_ALG socket opened by uid=%s exe=%s", ev.UID, ev.Exe),
			Details: fmt.Sprintf(
				"Audit event: timestamp=%s serial=%s\nauid=%s uid=%s comm=%q exe=%q\n"+
					"AF_ALG is essentially never used by cPanel/PHP workloads. This is\n"+
					"the kernel-level exploit signature for CVE-2026-31431 (\"Copy Fail\").\n"+
					"Investigate this process immediately and consider unloading algif_aead\n"+
					"(modprobe -r algif_aead af_alg) and adding a modprobe.d blacklist.",
				ev.Timestamp, ev.Serial, ev.AUID, ev.UID, ev.Comm, ev.Exe,
			),
		})
		if !highestSet || ev.after(highest) {
			highest = ev
			highestSet = true
		}
	}

	if highestSet {
		st.SetRaw(afAlgCursorKey, encodeCursor(highest))
	}
	return findings
}

func encodeCursor(ev afAlgEvent) string { return ev.Timestamp + ":" + ev.Serial }

func decodeCursor(s string) afAlgEvent {
	if s == "" {
		return afAlgEvent{}
	}
	colon := strings.Index(s, ":")
	if colon < 0 {
		return afAlgEvent{}
	}
	return afAlgEvent{Timestamp: s[:colon], Serial: s[colon+1:]}
}
