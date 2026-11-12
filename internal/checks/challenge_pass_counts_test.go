package checks

import (
	"testing"
	"time"
)

type passedIPList struct {
	mockIPList
	passes map[string]time.Time
}

func (p *passedIPList) Passes() map[string]time.Time { return p.passes }

// Lines an address logged before it passed a challenge are what it answered:
// they must not count against it again, while its later lines still do.
func TestLegacyCountsSkipLinesFromBeforeAPass(t *testing.T) {
	prev := challengeIPList
	t.Cleanup(func() { SetChallengeIPList(prev) })
	const ip = "203.0.113.30"
	passedAt := time.Date(2026, 5, 20, 18, 0, 30, 0, time.FixedZone("", 3*3600))
	SetChallengeIPList(&passedIPList{mockIPList: mockIPList{ips: map[string]bool{}}, passes: map[string]time.Time{ip: passedAt}})

	stats := newDomlogStats()
	feed := func(clock, request string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			rec, ok := parseAccessLogRecord(ip + ` - - [20/May/2026:` + clock + ` +0300] "` + request + ` HTTP/1.1" 200 0 "-" "Mozilla/5.0"`)
			if !ok {
				t.Fatalf("fixture line rejected: %s %s", clock, request)
			}
			stats.scan(rec, nil, nopBotClassifier{})
		}
	}
	for _, at := range []string{"18:00:00", "18:00:30"} {
		feed(at, "GET /?author=1", 6)
		feed(at, "POST /wp-login.php", 20)
		feed(at, "POST /xmlrpc.php", 31)
	}
	if stats.userEnum[ip] != 0 || stats.wpLogin[ip] != 0 || stats.xmlrpc[ip] != 0 {
		t.Fatalf("lines up to the pass still counted: enum=%d login=%d xmlrpc=%d", stats.userEnum[ip], stats.wpLogin[ip], stats.xmlrpc[ip])
	}

	feed("18:01:00", "GET /?author=1", 5)
	feed("18:01:00", "POST /wp-login.php", 2)
	feed("18:01:00", "POST /xmlrpc.php", 3)
	if stats.userEnum[ip] != 5 || stats.wpLogin[ip] != 2 || stats.xmlrpc[ip] != 3 {
		t.Fatalf("lines after the pass not counted: enum=%d login=%d xmlrpc=%d", stats.userEnum[ip], stats.wpLogin[ip], stats.xmlrpc[ip])
	}
}
