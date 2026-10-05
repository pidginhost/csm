package checks

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	_ "time/tzdata" // the DST fixtures must not depend on the host's zone files

	"github.com/pidginhost/csm/internal/admission"
)

func writeLegacyState(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, blockStateFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Spec 5.4 migration: the legacy hour's count is dated at the end of that
// local-time hour, the latest instant any of its blocks could have run.
func TestLegacyBlockSpendDatesTheCountAtTheEndOfItsHour(t *testing.T) {
	zone := time.FixedZone("UTC+3", 3*60*60)
	now := time.Date(2026, 10, 4, 14, 20, 0, 0, zone)
	dir := writeLegacyState(t, `{"ips":[{"ip":"192.0.2.7","reason":"r","blocked_at":"2026-10-04T14:05:00+03:00","expires_at":"2026-10-05T14:05:00+03:00"}],"pending":[{"ip":"2001:db8::7","reason":"r","check":"ssh_brute","severity":2}],"cleanup_pending":["198.51.100.4"],"blocks_this_hour":12,"hour_key":"2026-10-04T14","rate_limit_warned_hour":"2026-10-04T14"}`)
	spend, err := LegacyBlockSpend(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := (admission.LegacySpend{Units: 12, At: time.Date(2026, 10, 4, 15, 0, 0, 0, zone)}); spend.Units != want.Units || !spend.At.Equal(want.At) || spend.Unknown {
		t.Fatalf("spend = %+v, want %+v", spend, want)
	}
	// The previous hour still counts until it has left the window.
	prev := writeLegacyState(t, `{"ips":[],"blocks_this_hour":5,"hour_key":"2026-10-04T13"}`)
	if spend, err = LegacyBlockSpend(prev, now); err != nil || spend.Units != 5 || !spend.At.Equal(time.Date(2026, 10, 4, 14, 0, 0, 0, zone)) {
		t.Fatalf("previous hour = %+v, %v", spend, err)
	}
	if spend, err = LegacyBlockSpend(prev, time.Date(2026, 10, 4, 15, 0, 0, 0, zone)); err != nil || spend.Units != 0 {
		t.Fatalf("an hour that left the window = %+v, %v", spend, err)
	}
	// A clock stepped back leaves a later hour: it counts until its own
	// window ends.
	ahead := writeLegacyState(t, `{"ips":[],"blocks_this_hour":3,"hour_key":"2026-10-04T18"}`)
	if spend, err = LegacyBlockSpend(ahead, now); err != nil || spend.Units != 3 || !spend.At.Equal(time.Date(2026, 10, 4, 19, 0, 0, 0, zone)) {
		t.Fatalf("future hour = %+v, %v", spend, err)
	}
}

// A local hour that repeats when the clocks fall back counts until the end
// of its later instance.
func TestLegacyBlockSpendTakesTheLaterOfARepeatedHour(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	// 2026-11-01 01:00-02:00 occurs twice in New York.
	now := time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC).In(ny)
	dir := writeLegacyState(t, `{"ips":[],"blocks_this_hour":4,"hour_key":"2026-11-01T01"}`)
	spend, err := LegacyBlockSpend(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 11, 1, 7, 0, 0, 0, time.UTC); spend.Units != 4 || !spend.At.Equal(want) {
		t.Fatalf("repeated hour = %+v, want end %v", spend, want)
	}
}

// No legacy file means no legacy blocks: nothing to import.
func TestLegacyBlockSpendWithoutAFileIsZero(t *testing.T) {
	spend, err := LegacyBlockSpend(t.TempDir(), time.Now())
	if err != nil || spend != (admission.LegacySpend{}) {
		t.Fatalf("spend = %+v, %v", spend, err)
	}
}

// The whole file must validate. A damaged or unreadable file is an error,
// never zero spend: a failed import is not an empty ledger.
func TestLegacyBlockSpendRefusesADamagedFile(t *testing.T) {
	now := time.Date(2026, 10, 4, 14, 20, 0, 0, time.UTC)
	for name, body := range map[string]string{
		"not json":              `{"blocks_this_hour":`,
		"null state":            `null`,
		"empty state":           `{}`,
		"missing counter":       `{"hour_key":"2026-10-04T14"}`,
		"null counter":          `{"blocks_this_hour":null,"hour_key":"2026-10-04T14"}`,
		"null hour":             `{"blocks_this_hour":0,"hour_key":null}`,
		"duplicate counter":     `{"blocks_this_hour":7,"blocks_this_hour":0,"hour_key":"2026-10-04T14"}`,
		"nested duplicate":      `{"ips":[{"ip":"bad","ip":"192.0.2.1"}],"blocks_this_hour":0,"hour_key":""}`,
		"case duplicate":        `{"blocks_this_hour":7,"BLOCKS_THIS_HOUR":0,"hour_key":"2026-10-04T14"}`,
		"folded duplicate":      `{"blocks_this_hour":7,"block\u017f_this_hour":0,"hour_key":"2026-10-04T14"}`,
		"case alias":            `{"Blocks_This_Hour":0,"hour_key":""}`,
		"trailing data":         `{"blocks_this_hour":1,"hour_key":"2026-10-04T14"} {}`,
		"unknown field":         `{"blocks_this_hour":1,"hour_key":"2026-10-04T14","extra":1}`,
		"negative count":        `{"blocks_this_hour":-1,"hour_key":"2026-10-04T14"}`,
		"count without an hour": `{"blocks_this_hour":2,"hour_key":""}`,
		"malformed hour":        `{"blocks_this_hour":2,"hour_key":"2026-10-04 14"}`,
		"malformed warned hour": `{"blocks_this_hour":0,"hour_key":"","rate_limit_warned_hour":"14"}`,
		"far future zero count": `{"blocks_this_hour":0,"hour_key":"2026-10-06T14"}`,
		"far future hour":       `{"blocks_this_hour":2,"hour_key":"2026-10-06T14"}`,
		"bad blocked address":   `{"ips":[{"ip":"192.0.2.300"}],"blocks_this_hour":0,"hour_key":""}`,
		"bad pending address":   `{"pending":[{"ip":"bad"}],"blocks_this_hour":0,"hour_key":""}`,
		"bad cleanup address":   `{"cleanup_pending":["192.0.2.0/24"],"blocks_this_hour":0,"hour_key":""}`,
		"wrong type":            `{"blocks_this_hour":"7","hour_key":"2026-10-04T14"}`,
	} {
		if spend, err := LegacyBlockSpend(writeLegacyState(t, body), now); err == nil {
			t.Errorf("%s: accepted as %+v", name, spend)
		}
	}
	unreadable := t.TempDir()
	if err := os.Mkdir(filepath.Join(unreadable, blockStateFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if spend, err := LegacyBlockSpend(unreadable, now); err == nil {
		t.Errorf("an unreadable file was accepted as %+v", spend)
	}
}

// A half-hour fallback does not add another whole hour to the import.
func TestLegacyBlockSpendDatesAHalfHourFallback(t *testing.T) {
	loc, err := time.LoadLocation("Australia/Lord_Howe")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 4, 4, 14, 45, 0, 0, time.UTC).In(loc)
	dir := writeLegacyState(t, `{"blocks_this_hour":4,"hour_key":"2026-04-05T01"}`)
	spend, err := LegacyBlockSpend(dir, now)
	want := time.Date(2026, 4, 4, 15, 30, 0, 0, time.UTC)
	if err != nil || spend.Units != 4 || !spend.At.Equal(want) {
		t.Fatalf("half-hour fallback = %+v, %v; want %v", spend, err, want)
	}
}

// A forward step may leave a local hour with no first minute.
func TestLegacyBlockSpendDatesAPartialHour(t *testing.T) {
	loc, err := time.LoadLocation("Australia/Lord_Howe")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 3, 15, 45, 0, 0, time.UTC).In(loc)
	dir := writeLegacyState(t, `{"blocks_this_hour":4,"hour_key":"2026-10-04T02"}`)
	spend, err := LegacyBlockSpend(dir, now)
	want := time.Date(2026, 10, 3, 16, 0, 0, 0, time.UTC)
	if err != nil || spend.Units != 4 || !spend.At.Equal(want) {
		t.Fatalf("partial hour: %+v, %v; want %v", spend, err, want)
	}
}
