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
