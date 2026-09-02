package checks

import (
	"strings"
	"time"
)

// syslogLineTime returns the time a syslog line was written, from either the
// traditional BSD prefix ("Sep  2 04:12:33", no year, local time) or an
// RFC 3339 prefix as rsyslog writes with high-precision timestamps. The BSD
// form takes its year from now; a result more than a day in the future
// belongs to the previous year (a January read of December lines). ok is
// false when the line carries neither.
func syslogLineTime(line string, now time.Time) (time.Time, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
		return t, true
	}
	if len(fields) < 3 || !isSyslogTimestampPrefix(fields) {
		return time.Time{}, false
	}
	stamp := fields[0] + " " + fields[1] + " " + fields[2]
	t, err := time.ParseInLocation("Jan _2 15:04:05", stamp, now.Location())
	if err != nil {
		return time.Time{}, false
	}
	t = t.AddDate(now.Year(), 0, 0)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, true
}
