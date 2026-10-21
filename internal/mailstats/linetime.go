// Package mailstats counts mail decisions from log lines for the Email
// Security page.
package mailstats

import (
	"strings"
	"time"
)

// LineTime reads the time a mail log line starts with: Exim's date and time
// with an optional zone, a classic syslog stamp, or RFC 3339. A time without
// a zone is read in loc. A line with no readable time, or a time more than
// an hour after fallback, gets fallback.
func LineTime(line string, loc *time.Location, fallback time.Time) time.Time {
	t, ok := lineTime(line, loc, fallback)
	if !ok || t.Sub(fallback) > time.Hour {
		return fallback
	}
	return t
}

func lineTime(line string, loc *time.Location, fallback time.Time) (time.Time, bool) {
	first, _, _ := strings.Cut(line, " ")
	if t, err := time.Parse(time.RFC3339, first); err == nil {
		return t, true
	}
	if len(line) >= 25 {
		if t, err := time.Parse(time.DateTime+" -0700", line[:25]); err == nil {
			return t, true
		}
	}
	if len(line) >= 19 {
		if t, err := time.ParseInLocation(time.DateTime, line[:19], loc); err == nil {
			return t, true
		}
	}
	if len(line) >= 15 {
		if t, err := time.ParseInLocation(time.Stamp, line[:15], loc); err == nil {
			// A syslog stamp has no year. A stamp that lands more than a
			// day ahead of fallback was written last year.
			t = time.Date(fallback.In(loc).Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, loc)
			if t.Sub(fallback) > 24*time.Hour {
				t = t.AddDate(-1, 0, 0)
			}
			return t, true
		}
	}
	return time.Time{}, false
}
