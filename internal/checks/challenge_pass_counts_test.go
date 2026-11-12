package checks

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/challenge"
	"github.com/pidginhost/csm/internal/config"
)

type passedIPList struct {
	mockIPList
	passes map[string]time.Time
	cutoff time.Time
}

func (p *passedIPList) Passes() (map[string]time.Time, time.Time) { return p.passes, p.cutoff }

// Lines an address logged before it passed a challenge are what it answered:
// they must not count against it again, while its later lines still do.
func TestLegacyCountsSkipLinesFromBeforeAPass(t *testing.T) {
	prev := challengeIPList
	t.Cleanup(func() { SetChallengeIPList(prev) })
	const ip = "203.0.113.30"
	passedAt := time.Date(2026, 5, 20, 18, 0, 30, 0, time.FixedZone("", 3*3600))
	SetChallengeIPList(&passedIPList{mockIPList: mockIPList{ips: map[string]bool{}}, passes: map[string]time.Time{ip: passedAt}})

	stats := newDomlogStatsAt(passedAt.Add(time.Minute))
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

func TestForgottenPassDoesNotReviveOldLogEvidence(t *testing.T) {
	prev := challengeIPList
	t.Cleanup(func() { SetChallengeIPList(prev) })
	const ip = "203.0.113.30"
	now := time.Now()
	SetChallengeIPList(&passedIPList{passes: map[string]time.Time{}, cutoff: now.Add(-challenge.PassMemory)})
	stats := newDomlogStatsAt(now)
	for _, uri := range []string{"/wp-login.php", "/xmlrpc.php", "/?author=1"} {
		stats.scan(accessLogRecord{RemoteIP: ip, Time: now.Add(-8 * 24 * time.Hour), Method: "POST", URI: uri}, nil, nopBotClassifier{})
	}
	if stats.wpLogin[ip] != 0 || stats.xmlrpc[ip] != 0 || stats.userEnum[ip] != 0 {
		t.Fatalf("evidence outlived pass memory: login=%d xmlrpc=%d enum=%d", stats.wpLogin[ip], stats.xmlrpc[ip], stats.userEnum[ip])
	}
	// Unknown timestamps cannot be treated as answered, and a new attack
	// must still count even when the address once passed.
	for _, at := range []time.Time{{}, now} {
		for _, uri := range []string{"/wp-login.php", "/xmlrpc.php", "/?author=1"} {
			stats.scan(accessLogRecord{RemoteIP: ip, Time: at, Method: "POST", URI: uri}, nil, nopBotClassifier{})
		}
	}
	if stats.wpLogin[ip] != 2 || stats.xmlrpc[ip] != 2 || stats.userEnum[ip] != 2 {
		t.Fatalf("unanswered evidence lost: login=%d xmlrpc=%d enum=%d", stats.wpLogin[ip], stats.xmlrpc[ip], stats.userEnum[ip])
	}
}

func TestPassedRequestsDoNotAttributeDistributedAbuse(t *testing.T) {
	prev := challengeIPList
	t.Cleanup(func() { SetChallengeIPList(prev) })
	now := time.Now()
	cfg := &config.Config{}
	cfg.Thresholds.HTTPDistributedMinIPs = 1
	const ip = "203.0.113.30"
	SetChallengeIPList(&passedIPList{passes: map[string]time.Time{ip: now.Add(-time.Minute)}})
	for _, tc := range []struct{ uri, check string }{{"/wp-login.php", "wp_login_bruteforce"}, {"/xmlrpc.php", "xmlrpc_abuse"}} {
		t.Run(tc.check, func(t *testing.T) {
			stats := newDomlogStatsAt(now)
			stats.scan(accessLogRecord{RemoteIP: ip, Time: now.Add(-2 * time.Minute), Method: "POST", URI: tc.uri, Domain: "answered.example"}, cfg, nopBotClassifier{})
			stats.scan(accessLogRecord{RemoteIP: ip, Time: now, Method: "POST", URI: tc.uri, Domain: "current.example"}, cfg, nopBotClassifier{})
			got := stats.emitDistributedFlood(cfg, []alert.Finding{{Check: tc.check, SourceIP: ip}})
			if len(got) != 1 || got[0].Domain != "current.example" {
				t.Fatalf("distributed attribution includes answered requests: %+v", got)
			}
		})
	}
}

func TestPassTimestampAndAddressForms(t *testing.T) {
	prev := challengeIPList
	t.Cleanup(func() { SetChallengeIPList(prev) })
	const ip = "203.0.113.30"
	passed := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	SetChallengeIPList(&passedIPList{passes: map[string]time.Time{ip: passed}})
	for _, tc := range []struct {
		stamp string
		want  int
	}{
		{"12/Nov/2026:15:00:00 +0300", 0},
		{"12/Nov/2026:07:00:00 -0500", 0},
		{"12/Nov/2026:15:00:01 +0300", 1},
		{"invalid", 1},
	} {
		t.Run(tc.stamp, func(t *testing.T) {
			stats := newDomlogStatsAt(passed.Add(time.Minute))
			rec, ok := parseAccessLogRecord(`::ffff:203.0.113.30 - - [` + tc.stamp + `] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`)
			if !ok {
				t.Fatal("fixture rejected")
			}
			stats.scan(rec, nil, nopBotClassifier{})
			if got := stats.wpLogin[ip]; got != tc.want {
				t.Fatalf("count = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRecentPassStillRoutesAndHardBlocks(t *testing.T) {
	prevList, prevBlocker := challengeIPList, getIPBlocker()
	t.Cleanup(func() { SetChallengeIPList(prevList); SetIPBlocker(prevBlocker) })
	list := challenge.NewIPList(filepath.Join(t.TempDir(), "challenge.txt"))
	SetChallengeIPList(list)
	blocker := &recordingIPBlocker{}
	SetIPBlocker(blocker)
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Challenge.Enabled = true
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	setAutoResponseLive(cfg)
	const ip = "203.0.113.30"
	list.Add(ip, "test", time.Hour)
	if !list.MarkPassed(ip) {
		t.Fatal("pass not recorded")
	}
	routed, blocked := ChallengeThenBlock(cfg, []alert.Finding{{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: ip}})
	if len(routed) != 1 || len(blocked) != 0 || !list.Contains(ip) {
		t.Fatalf("pass bypassed routing: routed=%v blocked=%v", routed, blocked)
	}
	routed, blocked = ChallengeThenBlock(cfg, []alert.Finding{{Check: "waf_attack_blocked", Severity: alert.High, SourceIP: ip}})
	if len(routed) != 0 || len(blocked) != 1 || len(blocker.blocked) != 1 || blocker.blocked[0] != ip {
		t.Fatalf("pass bypassed hard block: routed=%v blocked=%v calls=%v", routed, blocked, blocker.blocked)
	}
}

func TestPassRetentionUsesSnapshotTime(t *testing.T) {
	prev := challengeIPList
	t.Cleanup(func() { SetChallengeIPList(prev) })
	SetChallengeIPList(challenge.NewIPList(filepath.Join(t.TempDir(), "challenge.txt")))
	now := time.Now()
	// A scan can wait on log discovery before it snapshots passes. A pass
	// retired during that delay must not revive its already answered lines.
	stats := newDomlogStatsAt(now.Add(-2 * time.Hour))
	stats.scan(accessLogRecord{RemoteIP: "203.0.113.30", Time: now.Add(-challenge.PassMemory - time.Hour), Method: "POST", URI: "/wp-login.php"}, nil, nopBotClassifier{})
	if stats.wpLogin["203.0.113.30"] != 0 {
		t.Fatal("snapshot expiry revived evidence after scan start")
	}
}
