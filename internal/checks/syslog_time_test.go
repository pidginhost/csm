package checks

import (
	"testing"
	"time"
)

func TestSyslogLineTime(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 0, 0, 0, time.Local)
	cases := []struct {
		name string
		line string
		want time.Time
		ok   bool
	}{
		{"bsd same year", "Jan  1 22:15:03 host pure-ftpd[1]: x", time.Date(2026, time.January, 1, 22, 15, 3, 0, time.Local), true},
		{"bsd previous year across new year", "Dec 31 23:59:58 host pure-ftpd[1]: x", time.Date(2025, time.December, 31, 23, 59, 58, 0, time.Local), true},
		{"rfc3339 with offset", "2026-01-01T22:15:03.123456+02:00 host pure-ftpd[1]: x", time.Date(2026, time.January, 1, 22, 15, 3, 123456000, time.FixedZone("", 7200)), true},
		{"no timestamp", "pure-ftpd[1]: (?@203.0.113.1) [WARNING] Authentication failed", time.Time{}, false},
		{"empty", "", time.Time{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := syslogLineTime(c.line, now)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if ok && !got.Equal(c.want) {
				t.Fatalf("time = %s, want %s", got, c.want)
			}
		})
	}
}

func TestSyslogLineTimeLeapDayAcrossNonLeapYears(t *testing.T) {
	for _, year := range []int{2025, 2026} {
		t.Run(time.Date(year, time.January, 1, 0, 0, 0, 0, time.UTC).Format("2006"), func(t *testing.T) {
			now := time.Date(year, time.January, 2, 3, 0, 0, 0, time.UTC)
			got, ok := syslogLineTime("Feb 29 22:15:03 host sshd[1]: Accepted", now)
			want := time.Date(2024, time.February, 29, 22, 15, 3, 0, time.UTC)
			if !ok || !got.Equal(want) {
				t.Fatalf("time = %s, ok = %v, want %s", got, ok, want)
			}
		})
	}
}

func TestSyslogLineTimeUsesTimestampDateForDSTOffset(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 2, 12, 0, 0, 0, loc)
	got, ok := syslogLineTime("Jan  2 03:04:05 host sshd[1]: Accepted", now)
	if !ok {
		t.Fatal("BSD timestamp was not parsed")
	}
	_, offset := got.Zone()
	if offset != -5*60*60 {
		t.Fatalf("January offset = %d, want EST offset %d", offset, -5*60*60)
	}
}
