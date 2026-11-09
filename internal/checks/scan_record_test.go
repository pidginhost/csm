package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// The newest record is chosen by log time, then file and offset, never by
// read order, and a record without a time or dated after the scan is never
// kept.
func TestKeepNewestOrdersByLogTimeThenPosition(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	rec := func(stream string, offset int64, at time.Time) scanRecord {
		return scanned(syslogRecord{text: "r", offset: offset, stream: stream}, at)
	}
	newest := rec("f:1:2", 10, now.Add(-time.Minute))
	for _, order := range [][]scanRecord{
		{rec("f:1:2", 50, now.Add(-2*time.Minute)), newest, rec("f:1:1", 90, now.Add(-time.Minute)), rec("f:1:2", 5, now.Add(-time.Minute))},
		{rec("f:1:2", 5, now.Add(-time.Minute)), rec("f:1:1", 90, now.Add(-time.Minute)), newest, rec("f:1:2", 50, now.Add(-2*time.Minute))},
	} {
		got := map[string]scanRecord{}
		for _, r := range append(order, rec("f:1:3", 1, time.Time{}), rec("f:1:3", 2, now.Add(2*time.Second))) {
			keepNewest(got, "ip", r, now)
		}
		if got["ip"] != newest {
			t.Fatalf("kept %+v, want %+v", got["ip"], newest)
		}
	}
	got := map[string]scanRecord{}
	keepNewest(got, "ip", rec("f:1:3", 2, now.Add(time.Second)), now)
	if _, ok := got["ip"]; !ok {
		t.Fatal("a record within the clock skew was dropped")
	}
}

// A scanned record keeps its cursor, not its text, and names itself as the
// record's readers do.
func TestScannedRecordNamesItsLine(t *testing.T) {
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.FixedZone("", 3600))
	r := scanned(syslogRecord{text: "line", offset: 7, stream: "f:1:2"}, at)
	o := r.observation(ProducerCpanelScan)
	if o.Producer != "cpanel_access_scan" || o.Stream != "f:1:2" || o.Cursor != alert.RecordCursor(7, "line") || !o.ObservedAt.Equal(at) || o.ObservedAt.Location() != time.UTC {
		t.Fatalf("observation %+v", o)
	}
	if (scanned(syslogRecord{text: "line", offset: 7}, at)).observation(ProducerCpanelScan) != (alert.Observation{}) {
		t.Fatal("a record without a file named an observation")
	}
	if scanned(syslogRecord{text: "line", offset: 7, stream: "f:1:2"}, time.Time{}) != (scanRecord{}) {
		t.Fatal("a record without a log time was kept")
	}
}

// A record still being written is never the newest: its reference would
// change when its line ends. The older complete record stays selected, and
// input holding only unfinished records names nothing.
func TestKeepNewestIgnoresUnfinishedRecords(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	tailRecordsFile(t, "older\nnewer")
	records := tailFileRecords("/anything", 10)
	if len(records) != 2 {
		t.Fatalf("records %+v, want two", records)
	}
	newest := map[string]scanRecord{}
	keepNewest(newest, "ip", scanned(records[0], now.Add(-time.Minute)), now)
	keepNewest(newest, "ip", scanned(records[1], now.Add(-time.Second)), now)
	if want := scanned(records[0], now.Add(-time.Minute)); newest["ip"] != want {
		t.Fatalf("kept %+v, want the older complete record %+v", newest["ip"], want)
	}

	tailRecordsFile(t, "only partial")
	partial := tailFileRecords("/anything", 10)
	none := map[string]scanRecord{}
	for _, r := range partial {
		keepNewest(none, "ip", scanned(r, now.Add(-time.Second)), now)
	}
	if len(partial) != 1 || len(none) != 0 {
		t.Fatalf("partial records %+v kept %+v, want nothing", partial, none)
	}
}
