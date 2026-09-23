package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/alert"
	bolt "go.etcd.io/bbolt"
)

// maxHistoryEntries is the maximum number of history entries to retain.
// It is a var (not const) so tests can override it.
var maxHistoryEntries = 100_000

// AppendHistory inserts findings into the history bucket with TimeKey keys.
// It increments the history:count counter and prunes oldest entries if the
// count exceeds maxHistoryEntries.
func (db *DB) AppendHistory(findings []alert.Finding) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))
		writer := newTimeKeyWriter(b)

		for i, f := range findings {
			val, err := json.Marshal(alert.SanitizeFinding(f))
			if err != nil {
				return err
			}
			key := nextHistoryKey(b, f.Timestamp, i)
			if err := writer.put([]byte(key), val); err != nil {
				return err
			}
			// Same transaction as the history insert: either both land or
			// neither does, so the daily aggregate can never drift.
			if err := incrStatsDaily(tx, f.Timestamp, f.Severity); err != nil {
				return err
			}
			if err := bumpLatestByCheck(tx, f.Check, f.Timestamp); err != nil {
				return err
			}
		}

		writer.settle()

		if err := incrCounter(tx, "history:count", len(findings)); err != nil {
			return err
		}

		// Cheap sweep against the bounded stats:daily bucket. Done here
		// (rather than on a timer) so the daily-aggregate path has a
		// single owner.
		if len(findings) > 0 {
			if err := pruneStatsDaily(tx, time.Now()); err != nil {
				return err
			}
		}

		// Prune oldest entries if count exceeds maxHistoryEntries.
		meta := tx.Bucket([]byte("meta"))
		var count int
		if v := meta.Get([]byte("history:count")); v != nil {
			_, _ = fmt.Sscanf(string(v), "%d", &count)
		}

		if count > maxHistoryEntries {
			excess := count - maxHistoryEntries
			c := b.Cursor()
			k, _ := c.First()
			for ; k != nil && excess > 0; excess-- {
				// Delete() moves the cursor to the next item, so we
				// must NOT call c.Next() after it.
				if err := c.Delete(); err != nil {
					return err
				}
				k, _ = c.First()
			}
			if err := setCounter(tx, "history:count", maxHistoryEntries); err != nil {
				return err
			}
		}

		return nil
	})
}

func nextHistoryKey(b *bolt.Bucket, timestamp time.Time, start int) string {
	for counter := start; ; counter++ {
		key := TimeKey(timestamp, counter)
		// Shutdown drains can persist separate batches whose findings carry
		// the same detector timestamp. Probe instead of overwriting history.
		if b.Get([]byte(key)) == nil {
			return key
		}
	}
}

// HistoryMark is a cheap value that changes whenever the history bucket
// does: its entry count and oldest and newest keys. Callers compare it to
// reuse results computed from history.
func (db *DB) HistoryMark() string {
	var mark string
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))
		if b == nil {
			return nil
		}
		count := ""
		if v := tx.Bucket([]byte("meta")).Get([]byte("history:count")); v != nil {
			count = string(v)
		}
		c := b.Cursor()
		first, _ := c.First()
		last, _ := c.Last()
		mark = count + "|" + string(first) + "|" + string(last)
		return nil
	})
	return mark
}

// ReadHistory reads findings from the history bucket, newest-first.
// It returns up to limit findings starting at offset, plus the total count.
func (db *DB) ReadHistory(limit, offset int) ([]alert.Finding, int) {
	total := db.getCounter("history:count")
	var results []alert.Finding

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))
		c := b.Cursor()

		// Skip offset entries from the end (newest first).
		skipped := 0
		k, v := c.Last()
		for ; k != nil && skipped < offset; k, v = c.Prev() {
			skipped++
		}

		// Collect up to limit entries.
		for ; k != nil && len(results) < limit; k, v = c.Prev() {
			var f alert.Finding
			if err := json.Unmarshal(v, &f); err == nil {
				results = append(results, f)
			}
		}

		return nil
	})

	return results, total
}

// ReadHistoryFiltered reads findings with optional filtering.
// Parameters:
//   - from, to: calendar dates or RFC 3339 instants (empty to skip)
//   - severity: filter by severity level (-1 for no filter)
//   - search: case-insensitive substring match on check/message/details (empty to skip)
func (db *DB) ReadHistoryFiltered(limit, offset int, from, to string, severity int, search string) ([]alert.Finding, int) {
	return db.ReadHistoryFilteredWithChecks(limit, offset, from, to, severity, search, nil)
}

// ParseHistoryBound reads one end of a history date range. A calendar date
// (YYYY-MM-DD) names a server-local day: as a start it is that day's
// midnight, as an end the next day's, so the whole day is included. An RFC
// 3339 instant is used as given; as an end it is exclusive. An empty bound
// is the zero time.
func ParseHistoryBound(s string, end bool) (time.Time, error) {
	return parseHistoryBoundIn(s, end, time.Local)
}

func parseHistoryBoundIn(s string, end bool, loc *time.Location) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	// Parse the calendar in UTC so a missing local midnight cannot normalize
	// the date into the preceding day before we choose the exclusive end.
	day, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("date %q is neither YYYY-MM-DD nor RFC 3339", s)
	}
	if end {
		day = day.AddDate(0, 0, 1)
	}
	// Walk the surrounding zone intervals to find the earliest instant of
	// the day. A repeated midnight uses its first occurrence; a skipped
	// midnight (or date) starts at the transition into the next valid time.
	for at := day.Add(-48 * time.Hour).In(loc); ; {
		_, offset := at.Zone()
		candidate := day.Add(-time.Duration(offset) * time.Second).In(loc)
		if candidate.Before(at) {
			candidate = at
		}
		_, zoneEnd := at.ZoneBounds()
		if zoneEnd.IsZero() || candidate.Before(zoneEnd) {
			return candidate, nil
		}
		at = zoneEnd
	}
}

// decodeHistoryEntry decodes one stored finding; a var so tests can count
// decodes.
var decodeHistoryEntry = func(v []byte, f *alert.Finding) error { return json.Unmarshal(v, f) }

// ReadHistoryFilteredWithChecks reads findings with optional filters, including
// an exact check-name set when checks is non-nil.
func (db *DB) ReadHistoryFilteredWithChecks(
	limit, offset int,
	from, to string,
	severity int,
	search string,
	checks map[string]bool,
) ([]alert.Finding, int) {
	var results []alert.Finding
	matched := 0
	searchLower := strings.ToLower(search)
	from, to = strings.TrimSpace(from), strings.TrimSpace(to)
	mayMatch := historyPrefilter(severity, searchLower, checks)

	var fromPrefix, toPrefix string
	if from != "" {
		if fromTime, err := ParseHistoryBound(from, false); err == nil {
			fromPrefix = timeKeyLowerBound(fromTime)
		} else {
			fromPrefix = ParseTimeKeyPrefix(from)
		}
	}
	if to != "" {
		if toTime, err := ParseHistoryBound(to, true); err == nil {
			// An exclusive upper bound: the next local midnight for a
			// date, the instant itself for an RFC 3339 end.
			toPrefix = timeKeyLowerBound(toTime)
		} else {
			toPrefix = ParseTimeKeyPrefix(to) + "99"
		}
	}

	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("history"))
		c := b.Cursor()

		// Seek to the first key at the exclusive upper bound, then step back so the
		// descending walk starts at the newest in-range entry. Without this the
		// loop walked (and skipped) every entry newer than `to`, which is O(N)
		// of the whole bucket when querying an old range on a large history.
		k, v := c.Last()
		if toPrefix != "" {
			if sk, _ := c.Seek([]byte(toPrefix)); sk != nil {
				// Seek lands on the first key >= toPrefix (out of range);
				// the previous key is the newest in-range entry.
				k, v = c.Prev()
			} else {
				// All keys are below toPrefix; Last() is already in range.
				k, v = c.Last()
			}
		}

		for ; k != nil; k, v = c.Prev() {
			key := string(k)

			// Defensive: anything still above the upper bound is out of range.
			if toPrefix != "" && key >= toPrefix {
				continue
			}

			// Time-range: if key is below fromPrefix, all remaining are older - stop.
			if fromPrefix != "" && key < fromPrefix {
				break
			}

			if !mayMatch(v) {
				continue
			}
			var f alert.Finding
			if err := decodeHistoryEntry(v, &f); err != nil {
				continue
			}

			// Severity filter.
			if severity >= 0 && int(f.Severity) != severity {
				continue
			}

			// Exact check-name filter.
			if checks != nil && !checks[f.Check] {
				continue
			}

			// Search filter.
			if search != "" && !containsLower(f.Check, searchLower) &&
				!containsLower(f.Message, searchLower) &&
				!containsLower(f.Details, searchLower) {
				continue
			}

			matched++
			if matched > offset && len(results) < limit {
				results = append(results, f)
			}
		}

		return nil
	})

	return results, matched
}

// containsLower checks if s contains substr using case-insensitive matching.
// substr must already be lowercase.
// historyPrefilter returns a test on a stored entry's JSON that is false only
// when the entry cannot pass the severity, check or search filter, so the
// walk that counts matches decodes only plausible entries. Each part applies
// only when the text it looks for is stored verbatim: JSON escapes quotes,
// backslashes, control characters, <, > and &, so a search for those is
// left to the decoded check.
func historyPrefilter(severity int, searchLower string, checks map[string]bool) func([]byte) bool {
	var sevNeedles [][]byte
	if severity >= 0 {
		sevNeedles = [][]byte{
			[]byte(fmt.Sprintf(`"severity":%d,`, severity)),
			[]byte(fmt.Sprintf(`"severity":%d}`, severity)),
		}
	}
	var checkNeedles [][]byte
	for name := range checks {
		if !storedVerbatim(name) {
			checkNeedles = nil
			break
		}
		checkNeedles = append(checkNeedles, []byte(`"check":"`+name+`"`))
	}
	var searchNeedle []byte
	if searchLower != "" && storedVerbatim(searchLower) {
		searchNeedle = []byte(searchLower)
	}
	return func(v []byte) bool {
		if sevNeedles != nil && !bytes.Contains(v, sevNeedles[0]) && !bytes.Contains(v, sevNeedles[1]) {
			return false
		}
		if checks != nil && checkNeedles != nil && !containsAnyBytes(v, checkNeedles) {
			return false
		}
		if searchNeedle != nil && !bytes.Contains(bytes.ToLower(v), searchNeedle) {
			return false
		}
		return true
	}
}

// storedVerbatim reports whether encoding/json writes s unchanged inside a
// JSON string.
func storedVerbatim(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == '"' || r == '\\' || r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029' || r == utf8.RuneError {
			return false
		}
	}
	return true
}

func containsAnyBytes(v []byte, needles [][]byte) bool {
	for _, n := range needles {
		if bytes.Contains(v, n) {
			return true
		}
	}
	return false
}

func containsLower(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), substr)
}
