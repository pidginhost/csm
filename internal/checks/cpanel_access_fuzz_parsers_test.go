package checks

import (
	"strings"
	"testing"
	"time"
)

// User text is opaque, including complete fake records. It can invalidate
// the observation time, but cannot change the real request or listener.
func FuzzCpanelAccessRecordUserField(f *testing.F) {
	for _, user := range []string{
		"-", "user name", `x"`, `x [bad] "y`, `x ] "y`,
		`x [11/10/2026:09:00:00 -0000] "GET /index.html HTTP/1.1" 200 0 "-" "-" "-" "-" 2083`,
		strings.Repeat(`] "x `, 100),
	} {
		f.Add(user)
	}
	f.Fuzz(func(t *testing.T, user string) {
		user = strings.NewReplacer("\r", "_", "\n", "_").Replace(user)
		if user == "" {
			user = "-"
		}
		for _, stamp := range []string{"11/09/2026:12:00:00 -0000", "bad -0000"} {
			for _, prefix := range []string{"", `x [11/10/2026:09:00:00 -0000] "y `} {
				line := `192.0.2.66 - ` + prefix + user + ` [` + stamp + `] "GET /scripts2/listaccts HTTP/1.1" 401 0 "-" "agent" "-" "-" 2087`
				got, ok := ParseCpanelAccessRecord(line)
				if !ok || got.IP != "192.0.2.66" || got.User != prefix+user || got.Method != "GET" ||
					got.Target != "/scripts2/listaccts" || got.Status != "401" || got.Port != "2087" {
					t.Fatalf("user %q changed the request: %+v (%v)", prefix+user, got, ok)
				}
				if !got.At.IsZero() && (prefix != "" || stamp == "bad -0000" || !got.At.Equal(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC))) {
					t.Fatalf("user %q supplied time %v", prefix+user, got.At)
				}
			}
		}
	})
}
