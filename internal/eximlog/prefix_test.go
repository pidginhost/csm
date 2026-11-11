package eximlog

import (
	"testing"
	"time"
)

func TestSplitPrefix(t *testing.T) {
	local := time.FixedZone("local", 3*3600)
	tests := []struct {
		name string
		line string
		ok   bool
		at   time.Time
		pid  string
		id   string
		rest string
	}{
		{
			name: "plain",
			line: "2026-11-09 10:00:00 1tAbCd-000123-Ab <= alice@example.com",
			ok:   true, at: time.Date(2026, 11, 9, 10, 0, 0, 0, local),
			id: "1tAbCd-000123-Ab", rest: "<= alice@example.com",
		},
		{
			name: "zone",
			line: "2026-11-09 10:00:00 +0000 1tAbCd-000123-Ab Completed",
			ok:   true, at: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC),
			id: "1tAbCd-000123-Ab", rest: "Completed",
		},
		{
			name: "pid",
			line: "2026-11-09 10:00:00 [12345] 1tAbCd-000123-Ab == bob@example.net R=dnslookup",
			ok:   true, at: time.Date(2026, 11, 9, 10, 0, 0, 0, local),
			pid: "12345", id: "1tAbCd-000123-Ab", rest: "== bob@example.net R=dnslookup",
		},
		{
			name: "zone and pid",
			line: "2026-11-09 10:00:00.250 -0500 [7] 1tAbCd-0000000Abcd-0Ab1 Frozen",
			ok:   true, at: time.Date(2026, 11, 9, 15, 0, 0, 250e6, time.UTC),
			pid: "7", id: "1tAbCd-0000000Abcd-0Ab1", rest: "Frozen",
		},
		{
			name: "pid before zone",
			line: "2026-11-09 10:00:00 [12345] +0300 1tAbCd-000123-Ab Frozen",
			ok:   true, at: time.Date(2026, 11, 9, 7, 0, 0, 0, time.UTC),
			pid: "12345", id: "1tAbCd-000123-Ab", rest: "Frozen",
		},
		{
			name: "no message",
			line: "2026-11-09 10:00:00 [12345] SMTP connection from [192.0.2.10]:4321",
			ok:   true, at: time.Date(2026, 11, 9, 10, 0, 0, 0, local),
			pid: "12345", rest: "SMTP connection from [192.0.2.10]:4321",
		},
		{
			name: "bracket that is not a pid stays in the text",
			line: "2026-11-09 10:00:00 [x1] 1tAbCd-000123-Ab Completed",
			ok:   true, at: time.Date(2026, 11, 9, 10, 0, 0, 0, local),
			rest: "[x1] 1tAbCd-000123-Ab Completed",
		},
		{name: "invalid zone", line: "2026-11-09 10:00:00 +2500 1tAbCd-000123-Ab Completed"},
		{name: "bad date", line: "2026-13-09 10:00:00 1tAbCd-000123-Ab Completed"},
		{name: "short", line: "2026-11-09"},
		{name: "empty", line: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, rest, ok := SplitPrefix(tt.line, local)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if !ok {
				return
			}
			if !p.Time.Equal(tt.at) {
				t.Errorf("time = %v, want %v", p.Time, tt.at)
			}
			if p.PID != tt.pid || p.MessageID != tt.id || rest != tt.rest {
				t.Errorf("pid, id, rest = %q, %q, %q; want %q, %q, %q", p.PID, p.MessageID, rest, tt.pid, tt.id, tt.rest)
			}
		})
	}
}

func TestSplitPrefixRejectsInvalidZoneAfterPID(t *testing.T) {
	local := time.FixedZone("local", 3*3600)
	for _, zone := range []string{"+2400", "-0060", "+2500", "+030", "-03:00"} {
		t.Run(zone, func(t *testing.T) {
			line := "2026-11-09 10:00:00 [12345] " + zone + " 1tAbCd-000123-Ab Completed"
			if p, rest, ok := SplitPrefix(line, local); ok || p != (Prefix{}) || rest != "" {
				t.Errorf("invalid zone returned prefix %+v, rest %q, ok %v", p, rest, ok)
			}
			if at, ok := LineTime(line, local); ok || !at.IsZero() {
				t.Errorf("invalid zone dated the line at %v", at)
			}
		})
	}
}
