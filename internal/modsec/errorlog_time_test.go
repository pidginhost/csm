package modsec

import (
	"testing"
	"time"
)

// The time of a ModSecurity error-log line comes only from the prefix the
// server wrote, in the server's local time; a time in the message is client
// text.
func TestErrorLogTime(t *testing.T) {
	at := func(nsec int) time.Time { return time.Date(2026, 11, 8, 8, 40, 0, nsec, time.Local) }
	for line, want := range map[string]time.Time{
		`[Sun Nov 08 08:40:00.123456 2026] [security2:error] [pid 123] [client 203.0.113.50:5555] ModSecurity: Access denied with code 403`: at(123456000),
		`[Sun Nov  8 08:40:00 2026] [error] [client 203.0.113.50] ModSecurity: Access denied with code 403`:                                 at(0),
		`2026/11/08 08:40:00 [error] 123#123: *1 [client 203.0.113.50] ModSecurity: Access denied with code 403`:                            at(0),
		`2026-11-08 08:40:00.123 [INFO] [1] [203.0.113.50:5555-1#APVH_example.test] [MODSEC] Access denied with code 403`:                   at(123000000),
		`2026-11-08 [NOTICE] [203.0.113.57:41920-13#APVH_*_server.example.com] [MODSEC] triggered!`:                                         {},
		`[client 203.0.113.50] ModSecurity: [Sun Nov 08 08:40:00 2026] Access denied with code 403`:                                         {},
		`[Sun Nov 08 08:40:00 2026] [core:error] [client 203.0.113.50:5555] File does not exist: /srv/www/ModSecurity: Access denied`:       {},
		`[Sun Nov 31 08:40:00 2026] [error] [client 203.0.113.50] ModSecurity: Access denied with code 403`:                                 {},
	} {
		got, ok := ErrorLogTime(line)
		if ok != !want.IsZero() || !got.Equal(want) {
			t.Errorf("time of %q is %v (%v), want %v", line, got, ok, want)
		}
	}
}
