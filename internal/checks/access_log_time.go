package checks

import "time"

// AccessLogTime reads the request time using the scheduled scan's parser,
// so both readers use the same peer-verification window for a record.
func AccessLogTime(line string) (time.Time, bool) {
	rec, ok := parseAccessLogRecord(line)
	return rec.Time, ok && !rec.Time.IsZero()
}
