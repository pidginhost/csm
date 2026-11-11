package checks

import (
	"slices"
	"testing"
	"time"
)

func TestParseSessionRecord(t *testing.T) {
	zoned := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name string
		line string
		want SessionRecord
	}{
		{
			name: "cPanel login",
			line: "[2026-04-12 10:00:00 +0000] info [cpaneld] 198.51.100.5 NEW admin:tok123 address=198.51.100.5,app=cpaneld,method=handle_form_login",
			want: SessionRecord{At: zoned, Level: "info", Service: "cpaneld", Origin: "198.51.100.5", Event: "NEW", Account: "admin", Session: "tok123",
				Detail: []string{"address=198.51.100.5,app=cpaneld,method=handle_form_login"}},
		},
		{
			name: "server-side password purge",
			line: "[2026-04-12 12:00:00 +0200] info [security] internal PURGE alice:tok123 password_change",
			want: SessionRecord{At: zoned, Level: "info", Service: "security", Origin: "internal", Event: "PURGE", Account: "alice", Session: "tok123",
				Detail: []string{"password_change"}},
		},
		{
			name: "WHM password purge",
			line: "[2026-04-12 10:00:00 +0000] info [whostmgr] 198.51.100.50 PURGE alice:token password_change",
			want: SessionRecord{At: zoned, Level: "info", Service: "whostmgr", Origin: "198.51.100.50", Event: "PURGE", Account: "alice", Session: "token",
				Detail: []string{"password_change"}},
		},
		{
			name: "bare timestamp is local time",
			line: "[2026-04-12 10:00:00] info [cpaneld] 203.0.113.5 NEW alice:token",
			want: SessionRecord{At: time.Date(2026, 4, 12, 10, 0, 0, 0, time.Local), Level: "info", Service: "cpaneld", Origin: "203.0.113.5", Event: "NEW",
				Account: "alice", Session: "token", Detail: []string{}},
		},
		{
			name: "unreadable timestamp keeps the record",
			line: "[not a timestamp] info [cpaneld] 203.0.113.5 NEW alice:token",
			want: SessionRecord{Level: "info", Service: "cpaneld", Origin: "203.0.113.5", Event: "NEW", Account: "alice", Session: "token", Detail: []string{}},
		},
		{
			name: "client text after the session cannot supply fields",
			line: "[2026-04-12 10:00:00 +0000] info [cpaneld] 198.51.100.5 NEW alice:tok address=203.0.113.9 [whostmgr] PURGE bob:tok password_change",
			want: SessionRecord{At: zoned, Level: "info", Service: "cpaneld", Origin: "198.51.100.5", Event: "NEW", Account: "alice", Session: "tok",
				Detail: []string{"address=203.0.113.9", "[whostmgr]", "PURGE", "bob:tok", "password_change"}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseSessionRecord(tt.line)
			if !ok {
				t.Fatal("record rejected")
			}
			if !got.At.Equal(tt.want.At) {
				t.Errorf("At = %v, want %v", got.At, tt.want.At)
			}
			got.At, tt.want.At = time.Time{}, time.Time{}
			if got.Level != tt.want.Level || got.Service != tt.want.Service || got.Origin != tt.want.Origin || got.Event != tt.want.Event ||
				got.Account != tt.want.Account || got.Session != tt.want.Session || !slices.Equal(got.Detail, tt.want.Detail) {
				t.Errorf("record = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseSessionRecordRejects(t *testing.T) {
	for _, line := range []string{
		"",
		"some random line",
		"]malformed[",
		"[cpaneld] only",
		"[whostmgr] 198.51.100.50",
		"PURGE   ",
		"[timestamp] internal PURGE",
		"[2026-04-12 10:00:00 +0000] info [cpaneld] 192.0.2.4 X",
		// Not cpsrvd's shape: the time is not bracketed, so the service sits in the time's place.
		"2026-04-11T12:00:00Z [cpaneld] 198.51.100.20 NEW alice:session method=handle_form_login",
		// A session record always names <account>:<session>.
		"[2026-04-12 10:00:00 +0000] info [cpaneld] 198.51.100.20 NEW bob method=handle_form_login",
		"[2026-04-12 10:00:00 +0000] info [cpaneld] 198.51.100.20 NEW :tok",
		"[2026-04-12 10:00:00 +0000] info [cpaneld] 198.51.100.20 NEW bob:",
		"[2026-04-12 10:00:00 +0000] info cpaneld 198.51.100.20 NEW bob:tok",
		"[2026-04-12 10:00:00 +0000] info [] 198.51.100.20 NEW bob:tok",
		" [2026-04-12 10:00:00 +0000] info [cpaneld] 198.51.100.20 NEW bob:tok",
	} {
		if r, ok := ParseSessionRecord(line); ok {
			t.Errorf("ParseSessionRecord(%q) = %+v, want rejected", line, r)
		}
	}
}

func TestSessionRecordClientAddr(t *testing.T) {
	for origin, want := range map[string]string{
		"198.51.100.5":       "198.51.100.5",
		"::ffff:192.0.2.7":   "192.0.2.7",
		"2001:DB8::5":        "2001:db8::5",
		"internal":           "",
		"not-an-address":     "",
		"2001:db8::5%eth0":   "",
		"198.51.100.5:2083":  "",
		"[2001:db8::5]:2083": "",
	} {
		got := ""
		if addr, ok := (SessionRecord{Origin: origin}).ClientAddr(); ok {
			got = addr.String()
		}
		if got != want {
			t.Errorf("ClientAddr(%q) = %q, want %q", origin, got, want)
		}
	}
}

func TestSessionRecordDetail(t *testing.T) {
	login, _ := ParseSessionRecord("[2026-04-12 10:00:00 +0000] info [cpaneld] 198.51.100.5 NEW alice:tok address=198.51.100.5,app=cpaneld,method=handle_form_login,path=form")
	if got := login.Attr("method"); got != "handle_form_login" {
		t.Errorf("method = %q", got)
	}
	if got := login.Attr("missing"); got != "" {
		t.Errorf("missing attribute = %q", got)
	}
	if login.CreatedByAPI() {
		t.Error("a form login is not an API session")
	}
	for _, method := range []string{"create_user_session", "create_session"} {
		r, _ := ParseSessionRecord("[2026-04-12 10:00:00 +0000] info [cpaneld] 198.51.100.5 NEW alice:tok method=" + method)
		if !r.CreatedByAPI() {
			t.Errorf("method=%s should be an API session", method)
		}
	}
	purge, _ := ParseSessionRecord("[2026-04-12 10:00:00 +0000] info [whostmgr] 198.51.100.50 PURGE alice:token password_change")
	if got := purge.Reason(); got != "password_change" {
		t.Errorf("reason = %q", got)
	}
	if got := (SessionRecord{}).Reason(); got != "" {
		t.Errorf("empty record reason = %q", got)
	}
}
