package checks

import (
	"strconv"
	"strings"
)

// afAlgEvent is the parsed view of a single SYSCALL record tagged with the
// csm_af_alg_socket auditd key. Fields are kept as strings because the
// downstream consumer is a human-readable Finding message.
type afAlgEvent struct {
	Timestamp string // e.g. "1761826283.452"
	Serial    string // e.g. "91234"
	UID       string
	AUID      string
	Comm      string
	Exe       string
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
