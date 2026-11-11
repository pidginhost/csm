package eximlog

import (
	"testing"
	"time"
)

// The arrival parser accepts whitespace between prefix fields. An explicit
// zone must not disappear into that whitespace and become local time.
func TestLineTimeZoneAfterWhitespace(t *testing.T) {
	local := time.FixedZone("local", 2*3600)
	const stamp = "2026-01-02 12:00:00.125"
	const body = " 1abc-0000-AB <= info@example.com H=relay.example [203.0.113.20] P=esmtpsa A=dovecot_plain:info@example.com S=123 T=\"+0530 -0700\""
	for _, spacing := range []struct{ name, gap string }{
		{"single space", " "}, {"double space", "  "}, {"tab after space", " \t"}, {"mixed spacing", " \t "},
	} {
		t.Run(spacing.name, func(t *testing.T) {
			for _, tc := range []struct {
				zone string
				want time.Time
			}{
				{"+0530", time.Date(2026, 1, 2, 6, 30, 0, 125000000, time.UTC)},
				{"-0700", time.Date(2026, 1, 2, 19, 0, 0, 125000000, time.UTC)},
				{"", time.Date(2026, 1, 2, 10, 0, 0, 125000000, time.UTC)},
				{"+2400", time.Time{}}, {"-0060", time.Time{}},
			} {
				line := stamp + spacing.gap + tc.zone + body
				// One prefix reader: a zone Exim cannot write voids the
				// arrival as well as its time.
				wantUser := "info@example.com"
				if tc.want.IsZero() {
					wantUser = ""
				}
				if got := AuthenticatedUser(line); got != wantUser {
					t.Fatalf("user = %q, want %q", got, wantUser)
				}
				got, ok := LineTime(line, local)
				if ok != !tc.want.IsZero() || !got.Equal(tc.want) {
					t.Errorf("zone %q after %q = %v, %v; want %v", tc.zone, spacing.gap, got, ok, tc.want)
				}
			}
		})
	}
}

func TestLineTimeLocalAndInvalid(t *testing.T) {
	ts, ok := LineTime("2026-04-22 14:55:43 1wFWBE-000000036n0-1PMK <= ...", time.UTC)
	if !ok || !ts.Equal(time.Date(2026, 4, 22, 14, 55, 43, 0, time.UTC)) {
		t.Fatalf("LineTime = %v, %v", ts, ok)
	}
	for _, line := range []string{"too short", "not-a-date-here-at-all 12345"} {
		if _, ok := LineTime(line, time.UTC); ok {
			t.Errorf("LineTime(%q) parsed", line)
		}
	}
}
