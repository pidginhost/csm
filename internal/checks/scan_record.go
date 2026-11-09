package checks

import (
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// scanRecord is a record a scan counted toward a finding: its file stream,
// cursor and offset, and the time its log wrote it. A scan that re-reads a
// window names a finding by its newest counted record, and by that record's
// own time: a re-read of unchanged input then names the same evidence,
// whatever the scan's clock says. It keeps the cursor, not the line, so a
// scan holding one record per address holds no request text.
type scanRecord struct {
	stream, cursor string
	offset         int64
	at             time.Time
	// kind is how the record's parser read the finding's address, when the
	// scan knows it only per record; unknown leaves the finding's kind.
	kind admission.Attribution
}

// scanned is the scan record of r written at at; zero without a log time.
func scanned(r syslogRecord, at time.Time) scanRecord {
	if at.IsZero() {
		return scanRecord{}
	}
	return scanRecord{stream: r.stream, cursor: alert.RecordCursor(r.offset, r.text), offset: r.offset, at: at}
}

// newer orders records by log time, then by file and offset, so the newest
// record is the same whichever order the scan read its files in.
func (r scanRecord) newer(o scanRecord) bool {
	switch {
	case !r.at.Equal(o.at):
		return r.at.After(o.at)
	case r.stream != o.stream:
		return r.stream > o.stream
	default:
		return r.offset > o.offset
	}
}

// scanRecordFutureSkew is how far past the scan's clock a record's log time
// may be. Admission refuses a root dated in the future.
const scanRecordFutureSkew = time.Second

// keepNewest keeps r under key when it is the newest record seen for it. A
// record without a file stream (one still being written) is never kept: its
// reference changes when its line ends. A record without a log time, or dated
// after the scan at now, is never kept either: a time a client wrote into the
// line cannot pin the observation.
func keepNewest(newest map[string]scanRecord, key string, r scanRecord, now time.Time) {
	if r.stream == "" {
		return
	}
	if r.at.IsZero() || r.at.After(now.Add(scanRecordFutureSkew)) {
		return
	}
	if cur, ok := newest[key]; !ok || r.newer(cur) {
		newest[key] = r
	}
}

// observation names r as every reader of its file names it; zero when the
// file has no identity.
func (r scanRecord) observation(producer admission.ProducerID) alert.Observation {
	if r.stream == "" || r.at.IsZero() {
		return alert.Observation{}
	}
	return alert.Observation{Producer: string(producer), Stream: r.stream, Cursor: r.cursor, ObservedAt: r.at.UTC()}
}

// stamp names r as the observation of f, with r's kind when it has one; f
// keeps no observation when the scan kept no record for it.
func (r scanRecord) stamp(f *alert.Finding, producer admission.ProducerID) {
	if o := r.observation(producer); o != (alert.Observation{}) {
		f.Observation = o
		if r.kind.Valid() {
			f.Attribution = r.kind
		}
	}
}
