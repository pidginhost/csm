package checks

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func FuzzParseSessionRecord(f *testing.F) {
	const prefix = "[2026-04-12 10:00:00 +0000] info [cpaneld] 198.51.100.5 NEW alice:tok "
	for _, line := range []string{
		"", "[]", "[bad time] info [security] internal PURGE alice:tok password_change",
		prefix + "address=198.51.100.5,app=cpaneld,method=handle_form_login",
		prefix + "address=198.51.100.5,method=create_session,method=handle_form_login",
		prefix + "[whostmgr] 203.0.113.5 PURGE bob:tok password_change",
	} {
		f.Add(line)
	}
	f.Fuzz(func(t *testing.T, line string) {
		r, ok := ParseSessionRecord(line)
		if !ok {
			if !reflect.DeepEqual(r, SessionRecord{}) {
				t.Fatal("rejected record returned partial evidence")
			}
		} else {
			if r.Level != "info" || r.Service == "" || strings.ContainsAny(r.Service, "[]") || r.Account == "" || r.Session == "" {
				t.Fatalf("invalid accepted record: %+v", r)
			}
			if strings.ContainsAny(line, "\r\n") {
				t.Fatal("accepted multiple physical lines")
			}
			if addr, valid := r.ClientAddr(); valid && (addr.Zone() != "" || addr.Is4In6()) {
				t.Fatalf("noncanonical client address: %s", addr)
			}
		}

		// Arbitrary client detail cannot replace the authenticated record header.
		r, ok = ParseSessionRecord(prefix + line)
		if ok && (!r.At.Equal(time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)) || r.Level != "info" ||
			r.Service != "cpaneld" || r.Origin != "198.51.100.5" || r.Event != "NEW" || r.Account != "alice" || r.Session != "tok") {
			t.Fatalf("detail replaced record fields: %+v", r)
		}
		r, ok = ParseSessionRecord(prefix + line + " method=handle_form_login")
		if ok && r.CreatedByAPI() {
			t.Fatal("client detail hid a direct form login")
		}
	})
}
