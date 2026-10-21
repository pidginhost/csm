// Package mailstats counts mail decisions from log lines for the Email
// Security page.
package mailstats

import (
	"strconv"
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
	first, rest, _ := strings.Cut(line, " ")
	if t, err := time.Parse(time.RFC3339, first); err == nil {
		return t, true
	}
	clock, rest, _ := strings.Cut(rest, " ")
	stamp := first + " " + clock
	zone, _, _ := strings.Cut(rest, " ")
	if strings.HasPrefix(zone, "+") || strings.HasPrefix(zone, "-") {
		t, err := time.Parse(time.DateTime+" -0700", stamp+" "+zone)
		return t, err == nil
	}
	if t, err := time.ParseInLocation(time.DateTime, stamp, loc); err == nil {
		return t, true
	}
	if len(line) >= 15 && (len(line) == 15 || line[15] == ' ') {
		if t, err := time.ParseInLocation(time.Stamp, line[:15], loc); err == nil {
			// A syslog stamp has no year. A stamp that lands more than a
			// day ahead of fallback was written last year.
			year := fallback.In(loc).Year()
			t = time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, loc)
			if t.Sub(fallback) > 24*time.Hour {
				year--
			}
			// Parsing with the inferred year rejects February 29 in a
			// non-leap year instead of normalizing it to March 1.
			t, err = time.ParseInLocation("2006 "+time.Stamp, strconv.Itoa(year)+" "+line[:15], loc)
			return t, err == nil
		}
	}
	return time.Time{}, false
}
