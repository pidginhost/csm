package daemon

import (
	"strings"
	"testing"
)

func TestAccessLogIPMethodPath(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantIP     string
		wantMethod string
		wantPath   string
		wantOK     bool
	}{
		{
			name:       "combined log POST wp-login",
			line:       `203.0.113.50 - - [11/Apr/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 123 "-" "Mozilla/5.0"`,
			wantIP:     "203.0.113.50",
			wantMethod: "POST",
			wantPath:   "/wp-login.php",
			wantOK:     true,
		},
		{
			name:       "IPv6 source",
			line:       `2001:db8::1 - - [11/Apr/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 0 "-" "curl"`,
			wantIP:     "2001:db8::1",
			wantMethod: "GET",
			wantPath:   "/index.html",
			wantOK:     true,
		},
		{
			name:       "tab-separated fields tolerated",
			line:       "10.0.0.1\t-\t-\t[11/Apr/2026:12:00:00 +0000]\t\"POST\t/api\tHTTP/1.1\"\t200\t1\t\"-\"\t\"x\"",
			wantIP:     "10.0.0.1",
			wantMethod: "POST",
			wantPath:   "/api",
			wantOK:     true,
		},
		{
			name:       "extra leading spaces",
			line:       `   198.51.100.7 - - [11/Apr/2026:12:00:00 +0000] "DELETE /x HTTP/1.1" 200 1 "-" "y"`,
			wantIP:     "198.51.100.7",
			wantMethod: "DELETE",
			wantPath:   "/x",
			wantOK:     true,
		},
		{
			name:   "truncated line under 7 fields",
			line:   `203.0.113.1 - - [11/Apr/2026:12:00:00 +0000]`,
			wantOK: false,
		},
		{
			name:   "empty",
			line:   ``,
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, method, path, ok := accessLogIPMethodPath(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v want=%v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if ip != tt.wantIP || method != tt.wantMethod || path != tt.wantPath {
				t.Fatalf("got ip=%q method=%q path=%q; want ip=%q method=%q path=%q",
					ip, method, path, tt.wantIP, tt.wantMethod, tt.wantPath)
			}
		})
	}
}

func BenchmarkAccessLogIPMethodPath(b *testing.B) {
	line := `203.0.113.50 - - [11/Apr/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 123 "-" "Mozilla/5.0"`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = accessLogIPMethodPath(line)
	}
}

func BenchmarkStringsFieldsBaseline(b *testing.B) {
	line := `203.0.113.50 - - [11/Apr/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 123 "-" "Mozilla/5.0"`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = strings.Fields(line)
	}
}
