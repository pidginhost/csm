package mailstats

import (
	"testing"
	"time"
	_ "time/tzdata"
)

func TestLineTimeExim(t *testing.T) {
	loc := time.FixedZone("host", 3*3600)
	fb := time.Date(2026, 10, 20, 12, 5, 0, 0, time.UTC)
	got := LineTime("2026-10-20 14:59:58 1tAbCd-000001-Ab <= a@example.com", loc, fb)
	if want := time.Date(2026, 10, 20, 11, 59, 58, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	got = LineTime("2026-10-20 12:00:00 +0000 1tAbCd-000001-Ab <= a@example.com", loc, fb)
	if want := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("explicit zone: got %v want %v", got, want)
	}
}

func TestLineTimeSyslog(t *testing.T) {
	loc := time.FixedZone("host", 3*3600)
	fb := time.Date(2026, 10, 20, 12, 5, 0, 0, time.UTC)
	got := LineTime("Oct 20 14:59:58 host dovecot: imap-login: x", loc, fb)
	if want := time.Date(2026, 10, 20, 11, 59, 58, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got = LineTime("Oct 20 20:00:00 host dovecot: x", loc, fb); !got.Equal(fb) {
		t.Fatalf("future stamp: got %v", got)
	}
	// The host's new year starts before UTC's.
	fb = time.Date(2026, 12, 31, 22, 0, 0, 0, time.UTC)
	got = LineTime("Jan  1 00:30:00 host dovecot: x", loc, fb)
	if want := time.Date(2026, 12, 31, 21, 30, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("local new year: got %v want %v", got, want)
	}
}

func TestLineTimeSyslogYearWrap(t *testing.T) {
	fb := time.Date(2027, 1, 1, 0, 0, 30, 0, time.UTC)
	got := LineTime("Dec 31 23:59:59 host dovecot: imap-login: x", time.UTC, fb)
	if got.Year() != 2026 {
		t.Fatalf("got %v", got)
	}
}

func TestLineTimeRFC3339(t *testing.T) {
	fb := time.Date(2026, 10, 20, 12, 0, 1, 0, time.UTC)
	got := LineTime("2026-10-20T15:00:00.123456+03:00 host dovecot: x", time.UTC, fb)
	if !got.Equal(time.Date(2026, 10, 20, 12, 0, 0, 123456000, time.UTC)) {
		t.Fatalf("got %v", got)
	}
}

func TestLineTimeFallbacks(t *testing.T) {
	fb := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for _, line := range []string{"", "imap-login: no prefix", "2026-13-40 99:00:00 x", "2026-10-20 18:00:00 future"} {
		if got := LineTime(line, time.UTC, fb); !got.Equal(fb) {
			t.Errorf("%q: got %v", line, got)
		}
	}
}

func TestLineTimeAmbiguousFallBack(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Bucharest")
	if err != nil {
		t.Fatal(err)
	}
	fb := time.Date(2026, 10, 25, 2, 0, 0, 0, time.UTC)
	got := LineTime("2026-10-25 03:30:00 1tAbCd-000001-Ab x", loc, fb)
	a := time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC) // EEST reading
	b := time.Date(2026, 10, 25, 1, 30, 0, 0, time.UTC) // EET reading
	if !got.Equal(a) && !got.Equal(b) {
		t.Fatalf("got %v, want %v or %v", got, a, b)
	}
}
