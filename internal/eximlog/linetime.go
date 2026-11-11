package eximlog

import "time"

// LineTime is the time Exim wrote at the start of line: the date, the time
// with any fraction log_selector +millisec adds, and the zone log_timezone
// adds, else the time in local. An explicit zone that is not a valid offset
// dates nothing; client text later in the line is never read.
func LineTime(line string, local *time.Location) (time.Time, bool) {
	p, _, ok := SplitPrefix(line, local)
	return p.Time, ok
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
