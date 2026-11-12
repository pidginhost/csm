package daemon

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// stalwartLine builds a synthetic Stalwart event line on a listener port.
func stalwartLine(at time.Time, event string, port int, ip, extra string) string {
	return fmt.Sprintf(`%s INFO Synthetic event (%s) listenerId = "l%d", localPort = %d, remoteIp = %s, remotePort = 40000%s`+"\n",
		at.UTC().Format(time.RFC3339), event, port, port, ip, extra)
}

const stalwartAccount = `, accountName = "user@example.com"`

var stalwartTestStart = time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)

func stalwartBruteConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Thresholds.MailBruteForceThreshold = 3
	cfg.Thresholds.MailBruteForceWindowMin = 10
	cfg.Thresholds.MailBruteForceSuppressMin = 60
	cfg.Thresholds.MailBruteForceMaxTracked = 100
	return cfg
}

// newStalwartAuthDaemon wires deterministic trackers (threshold 5) next to
// the Stalwart state.
func newStalwartAuthDaemon(t *testing.T, cfg *config.Config, overrides ...string) (*Daemon, *staticClock) {
	t.Helper()
	clock := &staticClock{t: stalwartTestStart}
	d := newStalwartTestDaemon(t, cfg, overrides...)
	d.smtpAuthTracker = newTestTracker(t, clock)
	d.mailAuthTracker = newTestMailTracker(t, clock)
	return d, clock
}

func feedStalwart(d *Daemon, lines ...string) []alert.Finding {
	var out []alert.Finding
	for _, l := range lines {
		out = append(out, d.handleStalwartLine(l, alert.Observation{}, d.currentCfg())...)
	}
	return out
}

func repeatLine(line string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = line
	}
	return out
}

func findingsOf(fs []alert.Finding, check string) []alert.Finding {
	var out []alert.Finding
	for _, f := range fs {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func TestStalwartAuthFailedSMTPFeedsSMTPTracker(t *testing.T) {
	d, _ := newStalwartAuthDaemon(t, stalwartBruteConfig())
	got := feedStalwart(d, repeatLine(stalwartLine(stalwartTestStart, "auth.failed", 587, "203.0.113.20", stalwartAccount), 5)...)
	brute := findingsOf(got, "smtp_bruteforce")
	if len(brute) != 1 || brute[0].SourceIP != "203.0.113.20" {
		t.Fatalf("findings = %+v, want one smtp_bruteforce for 203.0.113.20", got)
	}
	if d.mailAuthTracker.Size() != 0 {
		t.Fatal("SMTP failures reached the IMAP/POP3 tracker")
	}
}

func TestStalwartAuthFailedIMAPFeedsMailTracker(t *testing.T) {
	d, _ := newStalwartAuthDaemon(t, stalwartBruteConfig())
	got := feedStalwart(d, repeatLine(stalwartLine(stalwartTestStart, "auth.failed", 993, "203.0.113.21", stalwartAccount), 5)...)
	if brute := findingsOf(got, "mail_bruteforce"); len(brute) != 1 || brute[0].SourceIP != "203.0.113.21" {
		t.Fatalf("findings = %+v, want one mail_bruteforce", got)
	}
	if calls, _ := d.smtpAuthTracker.Stats(); calls != 0 {
		t.Fatal("IMAP failures reached the SMTP tracker")
	}
}

func TestStalwartPOP3AndSieveFeedMailTracker(t *testing.T) {
	for _, port := range []int{995, 4190} {
		d, _ := newStalwartAuthDaemon(t, stalwartBruteConfig())
		got := feedStalwart(d, repeatLine(stalwartLine(stalwartTestStart, "auth.failed", port, "203.0.113.22", stalwartAccount), 5)...)
		if len(findingsOf(got, "mail_bruteforce")) != 1 {
			t.Fatalf("port %d: findings = %+v, want mail_bruteforce", port, got)
		}
	}
}

func TestStalwartLoginAfterFailuresIsCompromise(t *testing.T) {
	d, _ := newStalwartAuthDaemon(t, stalwartBruteConfig())
	fail := stalwartLine(stalwartTestStart, "auth.failed", 993, "203.0.113.23", stalwartAccount)
	ok := stalwartLine(stalwartTestStart, "auth.success", 993, "203.0.113.23", stalwartAccount+", accountId = 7")
	got := feedStalwart(d, fail, fail, ok)
	comp := findingsOf(got, "mail_account_compromised")
	if len(comp) != 1 || comp[0].Mailbox != "user@example.com" || comp[0].SourceIP != "203.0.113.23" {
		t.Fatalf("findings = %+v, want one mail_account_compromised", got)
	}
}

func TestStalwartLoopbackEventsSkipTrackers(t *testing.T) {
	d, _ := newStalwartAuthDaemon(t, stalwartBruteConfig(), "10465:smtp")
	var lines []string
	for _, port := range []int{8080, 10465, 993} {
		for _, event := range []string{"auth.failed", "auth.success"} {
			lines = append(lines, repeatLine(stalwartLine(stalwartTestStart, event, port, "127.0.0.1", stalwartAccount), 6)...)
		}
	}
	if got := feedStalwart(d, lines...); len(got) != 0 {
		t.Fatalf("loopback events raised findings: %+v", got)
	}
	if d.mailAuthTracker.Size() != 0 || d.smtpAuthTracker.Size() != 0 {
		t.Fatal("loopback events reached a tracker")
	}
	if d.stalwart.webmail.size() != 0 {
		t.Fatal("loopback webmail failures were counted")
	}
}

func TestStalwartPrivateAndInfraSkipTrackers(t *testing.T) {
	cfg := stalwartBruteConfig()
	cfg.InfraIPs = []string{"192.0.2.10"}
	d, _ := newStalwartAuthDaemon(t, cfg)
	lines := append(repeatLine(stalwartLine(stalwartTestStart, "auth.failed", 993, "10.0.0.5", stalwartAccount), 6),
		repeatLine(stalwartLine(stalwartTestStart, "auth.failed", 587, "192.0.2.10", stalwartAccount), 6)...)
	if got := feedStalwart(d, lines...); len(got) != 0 {
		t.Fatalf("findings = %+v, want none", got)
	}
}

func TestStalwartHTTPFailuresAlertOnly(t *testing.T) {
	cfg := stalwartBruteConfig()
	d, _ := newStalwartAuthDaemon(t, cfg)
	fail := stalwartLine(stalwartTestStart, "auth.failed", 8080, "198.51.100.7", stalwartAccount)
	got := feedStalwart(d, repeatLine(fail, 3)...)
	if len(got) != 1 || got[0].Check != "stalwart_webmail_bruteforce" || got[0].SourceIP != "198.51.100.7" || got[0].Severity != alert.High {
		t.Fatalf("findings = %+v, want one stalwart_webmail_bruteforce", got)
	}
	if got[0].Attribution.Valid() {
		t.Fatalf("a forwarded address must carry no attribution, got %v", got[0].Attribution)
	}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs = true, true
	if checks.BlockableFinding(cfg, got[0]) {
		t.Fatal("a webmail finding must never be blockable")
	}
	if d.mailAuthTracker.Size() != 0 || d.smtpAuthTracker.Size() != 0 {
		t.Fatal("HTTP failures reached a blocking tracker")
	}
	if again := feedStalwart(d, stalwartLine(stalwartTestStart.Add(time.Minute), "auth.failed", 8080, "198.51.100.7", stalwartAccount)); len(again) != 0 {
		t.Fatalf("a failure inside the suppression period re-alerted: %+v", again)
	}
	after := stalwartTestStart.Add(61 * time.Minute)
	if late := feedStalwart(d, repeatLine(stalwartLine(after, "auth.failed", 8080, "198.51.100.7", stalwartAccount), 3)...); len(late) != 1 {
		t.Fatalf("after suppression: findings = %+v, want one", late)
	}
}

func TestStalwartHTTPSuccessIgnored(t *testing.T) {
	d, _ := newStalwartAuthDaemon(t, stalwartBruteConfig())
	got := feedStalwart(d, stalwartLine(stalwartTestStart, "auth.success", 443, "198.51.100.8", stalwartAccount))
	if len(got) != 0 || d.mailAuthTracker.Size() != 0 || d.smtpAuthTracker.Size() != 0 {
		t.Fatalf("an HTTP success reached a tracker: %+v", got)
	}
}

func TestStalwartWebmailFailuresOutsideWindowDoNotCount(t *testing.T) {
	d, _ := newStalwartAuthDaemon(t, stalwartBruteConfig())
	var got []alert.Finding
	for i := 0; i < 3; i++ {
		at := stalwartTestStart.Add(time.Duration(i) * 11 * time.Minute)
		got = append(got, feedStalwart(d, stalwartLine(at, "auth.failed", 8080, "198.51.100.9", stalwartAccount))...)
	}
	if len(got) != 0 {
		t.Fatalf("failures 11 minutes apart alerted: %+v", got)
	}
}

func TestStalwartUnknownPortAuthIgnored(t *testing.T) {
	d, _ := newStalwartAuthDaemon(t, stalwartBruteConfig())
	fail := stalwartLine(stalwartTestStart, "auth.failed", 2525, "203.0.113.24", stalwartAccount)
	if got := feedStalwart(d, repeatLine(fail, 6)...); len(got) != 0 {
		t.Fatalf("an unmapped port raised findings: %+v", got)
	}
	d, _ = newStalwartAuthDaemon(t, stalwartBruteConfig(), "2525:smtp")
	if got := feedStalwart(d, repeatLine(fail, 5)...); len(findingsOf(got, "smtp_bruteforce")) != 1 {
		t.Fatalf("with 2525:smtp, findings = %+v, want smtp_bruteforce", got)
	}
}

func TestStalwartWebmailTrackerCap(t *testing.T) {
	cfg := stalwartBruteConfig()
	cfg.Thresholds.MailBruteForceMaxTracked = 2
	d, _ := newStalwartAuthDaemon(t, cfg)
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		feedStalwart(d, stalwartLine(stalwartTestStart.Add(time.Duration(i)*time.Second), "auth.failed", 8080, ip, stalwartAccount))
	}
	if n := d.stalwart.webmail.size(); n > 2 {
		t.Fatalf("tracked %d addresses, cap is 2", n)
	}
}

func TestStalwartWebmailDisabledWithoutThreshold(t *testing.T) {
	d, _ := newStalwartAuthDaemon(t, &config.Config{})
	fail := stalwartLine(stalwartTestStart, "auth.failed", 8080, "198.51.100.10", stalwartAccount)
	if got := feedStalwart(d, repeatLine(fail, 20)...); len(got) != 0 {
		t.Fatalf("an unset threshold alerted: %+v", got)
	}
}
