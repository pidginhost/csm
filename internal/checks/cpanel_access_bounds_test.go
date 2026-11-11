package checks

import (
	"strings"
	"testing"
	"time"
)

func TestCpanelAccessClientTextCannotSupplyMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, line string
	}{
		{
			"user agent port",
			`192.0.2.66 - - [11/09/2026:12:00:00 -0000] "GET /scripts2/listaccts HTTP/1.1" 200 0 "-" "agent [bad] "GET / HTTP/1.1" 200 0 "-" "-" "host.example:2087"`,
		},
		{
			"user agent time",
			`192.0.2.66 - - [bad] "GET /execute/Themes/list HTTP/1.1" 401 0 "-" "agent [11/09/2026:12:00:00 -0000] "GET / HTTP/1.1" 200 0 "-" "-" "-"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := ParseCpanelAccessRecord(tc.line)
			if !ok || rec.IP != "192.0.2.66" || rec.Status != "" {
				t.Fatalf("ambiguous record lost or trusted: %+v (%v)", rec, ok)
			}
			if rec.Port != "" || !rec.At.IsZero() {
				t.Fatalf("client text supplied metadata: port %q, time %v", rec.Port, rec.At)
			}
		})
	}
}

func TestCpanelAccessCandidateAllocations(t *testing.T) {
	for _, tc := range []struct {
		name, candidate string
	}{
		{"statuses", `[bad] "GET / HTTP/1.1" 200 0 `},
		{"methods", `[bad] "\x50\x4f\x53\x54 / HTTP/1.1" 200 0 `},
		{"targets", `[bad] "POST /INDEX.HTML HTTP/1.1" 200 0 `},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cost := func(n int) float64 {
				line := `192.0.2.66 - x ` + strings.Repeat(tc.candidate, n) +
					`[11/09/2026:12:00:00 -0000] "GET / HTTP/1.1" 200 0 "-" "agent" "-" "-" 2096`
				return testing.AllocsPerRun(5, func() {
					rec, ok := ParseCpanelAccessRecord(line)
					if !ok || rec.Port != "2096" || rec.MayHaveStatus("401", "403") ||
						rec.TargetContains("absent") || rec.WebmailLogin() {
						t.Fatal("candidate traversal changed the record")
					}
					count := 0
					for range rec.Requests() {
						count++
					}
					if count != n+1 {
						t.Fatalf("got %d requests, want %d", count, n+1)
					}
				})
			}
			small, large := cost(4), cost(512)
			if large > small {
				t.Fatalf("allocations grow with candidates: %g for 4, %g for 512", small, large)
			}
		})
	}
}

func TestCpanelAccessCandidateWorkIsLinear(t *testing.T) {
	cost := func(n int) time.Duration {
		line := `192.0.2.66 - x ` + strings.Repeat(`[bad] "\x50OST /INDEX.HTML HTTP/1.1" 200 0 `, n) +
			`[11/09/2026:12:00:00 -0000] "GET /execute/Themes/list HTTP/1.1" 401 0 "-" "agent" "host.example:2087"`
		best := time.Duration(1<<63 - 1)
		for range 5 {
			start := time.Now()
			rec, ok := ParseCpanelAccessRecord(line)
			found := rec.TargetContains("/execute/") && rec.MayHaveStatus("401")
			elapsed := time.Since(start)
			if !ok || !found {
				t.Fatal("forged requests hid the real request or status")
			}
			best = min(best, elapsed)
		}
		return best
	}
	small, large := cost(2000), cost(16000)
	if large > 32*small+time.Millisecond {
		t.Fatalf("8x the candidates cost %v against %v", large, small)
	}
}

func TestCpanelEscapedMethodClassification(t *testing.T) {
	for _, tc := range []struct {
		method string
		login  bool
	}{
		{"POST", true}, {"pOsT", true}, {`\x50\x4f\x53\x54`, true},
		{`\x70ost`, true}, {`P%4fST`, false}, {`\x50OS`, false},
		{`POST\x58`, false}, {"GET", false},
	} {
		line := `192.0.2.66 - - [11/09/2026:12:00:00 -0000] "` + tc.method + ` /LOGIN/ HTTP/1.1" 401 0 "-" "agent" "-" "-" 2096`
		rec, ok := ParseCpanelAccessRecord(line)
		if !ok || rec.WebmailLogin() != tc.login {
			t.Errorf("method %q: webmail login %v (%v), want %v", tc.method, rec.WebmailLogin(), ok, tc.login)
		}
	}
}
