package checks

import (
	"strconv"
	"strings"
	"time"
)

// syslogLineTime returns the time a syslog line was written, from either the
// traditional BSD prefix ("Sep  2 04:12:33", no year, local time) or an
// RFC 3339 prefix as rsyslog writes with high-precision timestamps. The BSD
// form uses the most recent plausible year; a result more than a day in the
// future belongs to an earlier year (a January read of December lines). ok is
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
	parseYear := func(year int) (time.Time, error) {
		return time.ParseInLocation("2006 Jan _2 15:04:05", strconv.Itoa(year)+" "+stamp, now.Location())
	}
	// Eight years covers the largest gap between Gregorian leap years. This
	// also handles a leap-day record read more than one year later without
	// treating an unparseable timestamp as a current event.
	for yearsAgo := 0; yearsAgo <= 8; yearsAgo++ {
		t, err := parseYear(now.Year() - yearsAgo)
		if err == nil && !t.After(now.Add(24*time.Hour)) {
			return t, true
		}
	}
	return time.Time{}, false
}
