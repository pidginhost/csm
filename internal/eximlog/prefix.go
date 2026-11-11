package eximlog

import (
	"strings"
	"time"
)

// Prefix is what Exim writes before the text of a main log line: the time,
// the process ID when log_selector has +pid, and the message ID on lines
// about one message.
type Prefix struct {
	Time      time.Time
	PID       string
	MessageID string
}

// SplitPrefix reads the prefix that starts line and returns it with the text
// after it. The time carries the zone log_timezone writes, else local. An
// explicit zone that is not a valid offset dates nothing. A field that does
// not have the shape of a PID or message ID is left in the text.
func SplitPrefix(line string, local *time.Location) (Prefix, string, bool) {
	var p Prefix
	date, rest := nextField(line)
	clock, rest := nextField(rest)
	field, after := nextField(rest)
	if isPID(field) {
		// Exim writes the zone with the time, then the PID. A zone after
		// the PID is read too.
		p.PID, rest = field[1:len(field)-1], after
		field, after = nextField(rest)
	}
	stamp := date + " " + clock
	var err error
	if field != "" && (field[0] == '+' || field[0] == '-') {
		if !validOffset(field) {
			return Prefix{}, "", false
		}
		p.Time, err = time.Parse(time.DateTime+" -0700", stamp+" "+field)
		rest = after
	} else {
		p.Time, err = time.ParseInLocation(time.DateTime, stamp, local)
	}
	if err != nil {
		return Prefix{}, "", false
	}
	if field, after := nextField(rest); p.PID == "" && isPID(field) {
		p.PID, rest = field[1:len(field)-1], after
	}
	if field, after := nextField(rest); IsMessageID(field) {
		p.MessageID, rest = field, after
	}
	return p, strings.TrimLeft(rest, " \t"), true
}

func nextField(s string) (field, rest string) {
	s = strings.TrimLeft(s, " \t")
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

func isPID(field string) bool {
	return len(field) >= 3 && field[0] == '[' && field[len(field)-1] == ']' &&
		strings.Trim(field[1:len(field)-1], "0123456789") == ""
}

// IsMessageID reports whether field has the shape of an Exim message ID:
// three dash-separated base62 parts. Exim writes 6-6-2 or, from 4.97,
// 6-11-4; in a log line the position, not the length, proves the field is
// server-written.
func IsMessageID(field string) bool {
	parts := strings.Split(field, "-")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.Trim(part, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			return false
		}
	}
	return true
}
