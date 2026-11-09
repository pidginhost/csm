package eximlog

import (
	"strings"
	"time"
)

// LineTime is the time Exim wrote at the start of line: the date, the time
// with any fraction log_selector +millisec adds, and the zone log_timezone
// adds, else local time. An explicit zone that is not a valid offset dates
// nothing; client text later in the line is never read.
func LineTime(line string) (time.Time, bool) { return lineTimeIn(line, time.Local) }

func lineTimeIn(line string, local *time.Location) (time.Time, bool) {
	date, rest, _ := strings.Cut(line, " ")
	clock, rest, _ := strings.Cut(rest, " ")
	stamp := date + " " + clock
	// Arrival metadata accepts extra spacing here; it must not hide a zone
	// and silently turn an explicit offset into local time.
	rest = strings.TrimLeft(rest, " \t")
	if rest != "" && (rest[0] == '+' || rest[0] == '-') {
		zone, _, _ := strings.Cut(rest, " ")
		if !validOffset(zone) {
			return time.Time{}, false
		}
		at, err := time.Parse(time.DateTime+" -0700", stamp+" "+zone)
		return at, err == nil
	}
	at, err := time.ParseInLocation(time.DateTime, stamp, local)
	return at, err == nil
}

// validOffset reports whether zone is +hhmm or -hhmm with hh below 24 and
// mm below 60.
func validOffset(zone string) bool {
	if len(zone) != 5 {
		return false
	}
	for _, c := range zone[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return zone[1:3] < "24" && zone[3:5] < "60"
}
