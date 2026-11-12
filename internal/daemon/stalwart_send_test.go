package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/store"
)

func stalwartSendConfig() *config.Config {
	cfg := stalwartBruteConfig()
	cfg.EmailProtection.RateWarnThreshold = 1
	cfg.EmailProtection.RateCritThreshold = 50
	cfg.EmailProtection.RateWindowMin = 60
	return cfg
}

func stubStalwartPTR(t *testing.T, ptr string) {
	t.Helper()
	prev := stalwartPTR
	stalwartPTR = func(string) string { return ptr }
	t.Cleanup(func() { stalwartPTR = prev })
}

func resetStalwartSendState(t *testing.T) {
	t.Helper()
	resetEmailRateState()
	resetSenderProfileState()
	resetCloudRelayState()
	withMailBackendHost(t, false)
}

// stalwartSend logs in account on port from ip and queues one message to rcpts.
func stalwartLoginAndSend(port int, ip, account, from string, rcpts ...string) []string {
	quoted := make([]string, len(rcpts))
	for i, r := range rcpts {
		quoted[i] = `"` + r + `"`
	}
	return []string{
		stalwartLine(stalwartTestStart, "auth.success", port, ip, fmt.Sprintf(`, accountName = "%s", accountId = 7`, account)),
		stalwartLine(stalwartTestStart, "queue.authenticated-message-queued", port, ip,
			fmt.Sprintf(`, queueId = 1, from = "%s", to = [%s], size = 900`, from, strings.Join(quoted, ", "))),
	}
}

func senderDay(t *testing.T, user string) *store.SenderDay {
	t.Helper()
	v, ok := senderWindows.Load(user)
	if !ok {
		t.Fatalf("no sender window for %s", user)
	}
	w := v.(*senderWindow)
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.profile.Days[senderDayKey(time.Now())]
}

func TestStalwartQueueJoinsAuthSuccess(t *testing.T) {
	resetStalwartSendState(t)
	stubStalwartPTR(t, "mail.example.net")
	d, _ := newStalwartAuthDaemon(t, stalwartSendConfig())
	got := feedStalwart(d, stalwartLoginAndSend(587, "203.0.113.40", "user@example.com", "user@example.com", "a@example.org")...)
	rate := findingsOf(got, "email_rate_warning")
	if len(rate) != 1 || !strings.Contains(rate[0].Message, "user@example.com") {
		t.Fatalf("findings = %+v, want one email_rate_warning for the logged-in account", got)
	}
	if day := senderDay(t, "user@example.com"); day == nil || day.Sends != 1 || len(day.IPs) != 1 || day.IPs[0] != "203.0.113.40" {
		t.Fatalf("sender day = %+v, want one send from 203.0.113.40", day)
	}
}

func TestStalwartQueueWithoutLoginIgnored(t *testing.T) {
	resetStalwartSendState(t)
	d, _ := newStalwartAuthDaemon(t, stalwartSendConfig())
	send := stalwartLoginAndSend(587, "203.0.113.41", "user@example.com", "user@example.com", "a@example.org")[1]
	if got := feedStalwart(d, send); len(got) != 0 {
		t.Fatalf("a send with no login raised %+v", got)
	}
	if n := d.stalwart.stats.unattributed.Load(); n != 1 {
		t.Fatalf("unattributed = %d, want 1", n)
	}
}

func TestStalwartSendsKeepListenerPortsSeparate(t *testing.T) {
	resetStalwartSendState(t)
	stubStalwartPTR(t, "mail.example.net")
	d, _ := newStalwartAuthDaemon(t, stalwartSendConfig())
	first := stalwartLoginAndSend(465, "203.0.113.40", "first@example.com", "first@example.com", "a@example.org")
	second := stalwartLoginAndSend(587, "203.0.113.40", "second@example.com", "second@example.com", "b@example.org")
	for i := range first {
		first[i] = strings.ReplaceAll(first[i], `listenerId = "l465"`, `listenerId = "submission"`)
		second[i] = strings.ReplaceAll(second[i], `listenerId = "l587"`, `listenerId = "submission"`)
	}
	feedStalwart(d, first[0], second[0])
	got := feedStalwart(d, first[1], second[1])
	if rate := findingsOf(got, "email_rate_warning"); len(rate) != 2 {
		t.Fatalf("findings = %+v, want a separate rate warning for each account", got)
	}
	for _, account := range []string{"first@example.com", "second@example.com"} {
		if day := senderDay(t, account); day == nil || day.Sends != 1 {
			t.Fatalf("%s: sender day = %+v, want one send", account, day)
		}
	}
}

// A listener CSM cannot map, such as a local submission port, still carries
// sends: they count toward volume and recipients, never as an address signal.
func TestStalwartSendsOnUnknownPortCountVolumeOnly(t *testing.T) {
	resetStalwartSendState(t)
	stubStalwartPTR(t, "ec2-203-0-113-40.compute.amazonaws.com")
	d, _ := newStalwartAuthDaemon(t, stalwartSendConfig())
	var got []alert.Finding
	for i := 0; i < 3; i++ {
		got = append(got, feedStalwart(d, stalwartLoginAndSend(2525, "203.0.113.40", "user@example.com", "user@example.com", "a@example.org")...)...)
	}
	if relay := findingsOf(got, "email_cloud_relay_abuse"); len(relay) != 0 {
		t.Fatalf("an unmapped listener fed the cloud-relay check: %+v", relay)
	}
	if brute := findingsOf(got, "smtp_bruteforce"); len(brute) != 0 || d.smtpAuthTracker.Size() != 0 {
		t.Fatalf("an unmapped listener's logins reached a tracker: %+v", got)
	}
	if day := senderDay(t, "user@example.com"); day == nil || day.Sends != 3 || len(day.IPs) != 0 {
		t.Fatalf("sender day = %+v, want 3 sends and no address", day)
	}
}

// The field host's sites send through a loopback listener on a port Stalwart
// does not use by default. Those sends are counted without any port mapping.
func TestStalwartLocalSubmissionOnUnmappedPortCounted(t *testing.T) {
	resetStalwartSendState(t)
	d, _ := newStalwartAuthDaemon(t, stalwartSendConfig())
	for i := 0; i < 2; i++ {
		feedStalwart(d, stalwartLoginAndSend(10465, "127.0.0.1", "site@example.com", "site@example.com", "a@example.org")...)
	}
	if day := senderDay(t, "site@example.com"); day == nil || day.Sends != 2 {
		t.Fatalf("sender day = %+v, want 2 sends", day)
	}
}

// Webmail and JMAP logins can share a proxy connection, so their sends are
// not tied to an account, and IMAP, POP3 and ManageSieve logins, which never
// send, do not fill the connection memory.
func TestStalwartNonSendingListenersNotMatched(t *testing.T) {
	resetStalwartSendState(t)
	d, _ := newStalwartAuthDaemon(t, stalwartSendConfig())
	got := feedStalwart(d, stalwartLoginAndSend(8080, "198.51.100.60", "web@example.com", "web@example.com", "a@example.org")...)
	if len(got) != 0 {
		t.Fatalf("an HTTP-listener send raised %+v", got)
	}
	if _, ok := senderWindows.Load("web@example.com"); ok {
		t.Fatal("an HTTP-listener send was charged to an account")
	}
	for _, port := range []int{993, 995, 4190} {
		feedStalwart(d, stalwartLine(stalwartTestStart, "auth.success", port, "203.0.113.61", `, accountName = "imap@example.com", accountId = 8`))
	}
	if n := d.stalwart.sessions.size(); n != 0 {
		t.Fatalf("logins that never send were remembered: %d", n)
	}
}

// Sites send through a loopback listener, and a mapped SMTP listener from a
// private or loopback address: both count toward volume and recipients only.
func TestStalwartLocalSubmissionVolumeOnly(t *testing.T) {
	for _, tc := range []struct {
		port int
		ip   string
	}{{10465, "127.0.0.1"}, {10465, "10.0.0.5"}} {
		t.Run(fmt.Sprint(tc.port), func(t *testing.T) {
			resetStalwartSendState(t)
			stubStalwartPTR(t, "ec2-198-51-100-50.compute.amazonaws.com")
			d, _ := newStalwartAuthDaemon(t, stalwartSendConfig(), "10465:smtp")
			var got []alert.Finding
			for i := 0; i < 3; i++ {
				got = append(got, feedStalwart(d, stalwartLoginAndSend(tc.port, tc.ip, "site@example.com", "site@example.com", "a@example.org")...)...)
			}
			if relay := findingsOf(got, "email_cloud_relay_abuse"); len(relay) != 0 {
				t.Fatalf("a local or HTTP send fed the cloud-relay check: %+v", relay)
			}
			if day := senderDay(t, "site@example.com"); day == nil || day.Sends != 3 || len(day.IPs) != 0 || len(day.Countries) != 0 {
				t.Fatalf("sender day = %+v, want 3 sends and no address", day)
			}
		})
	}
}

func TestStalwartCloudRelayUsesPTR(t *testing.T) {
	resetStalwartSendState(t)
	stubStalwartPTR(t, "ec2-203-0-113-42.compute.amazonaws.com")
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
	d, _ := newStalwartAuthDaemon(t, stalwartSendConfig())
	var got []alert.Finding
	for _, ip := range []string{"203.0.113.42", "203.0.113.43", "203.0.113.42"} {
		got = append(got, feedStalwart(d, stalwartLoginAndSend(465, ip, "user@example.com", "user@example.com", "a@example.org")...)...)
	}
	relay := findingsOf(got, "email_cloud_relay_abuse")
	if len(relay) != 1 || relay[0].SourceIP != "203.0.113.42" {
		t.Fatalf("findings = %+v, want one cloud-relay finding naming 203.0.113.42", got)
	}
	if relay[0].Context != stalwartNoSuspendContext {
		t.Fatalf("context = %q", relay[0].Context)
	}
	if len(*calls) != 0 {
		t.Fatalf("suspension attempted on a Stalwart host: %v", *calls)
	}
}

// A bare account name has no domain of its own, and the envelope sender is
// whatever the sender typed: marking that domain would only quiet other
// mailboxes' rate alerts, so a bare account marks no domain.
func TestStalwartBareAccountMarksNoDomain(t *testing.T) {
	resetStalwartSendState(t)
	stubStalwartPTR(t, "mail.example.net")
	stubGeo(t, map[string]string{"203.0.113.44": "DE", "203.0.113.45": "FR", "203.0.113.46": "BR"})
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
	d, _ := newStalwartAuthDaemon(t, stalwartSendConfig())
	var got []alert.Finding
	for _, ip := range []string{"203.0.113.44", "203.0.113.45", "203.0.113.46"} {
		got = append(got, feedStalwart(d, stalwartLoginAndSend(587, ip, "john", "victim@example.org", "a@example.org")...)...)
	}
	sender := findingsOf(got, "email_compromised_account")
	if len(sender) != 1 || sender[0].Severity != alert.Critical {
		t.Fatalf("findings = %+v, want one Critical sender finding", got)
	}
	if sender[0].Context != stalwartNoSuspendContext {
		t.Fatalf("context = %q", sender[0].Context)
	}
	if hasRecentCompromisedFinding("example.org") {
		t.Fatal("the envelope sender's domain was marked: a sender can name any domain")
	}
	if len(*calls) != 0 {
		t.Fatalf("suspension attempted: %v", *calls)
	}
}

// An account with its own domain marks that domain.
func TestStalwartAddressAccountMarksItsDomain(t *testing.T) {
	resetStalwartSendState(t)
	stubStalwartPTR(t, "mail.example.net")
	stubGeo(t, map[string]string{"203.0.113.44": "DE", "203.0.113.45": "FR", "203.0.113.46": "BR"})
	stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
	d, _ := newStalwartAuthDaemon(t, stalwartSendConfig())
	for _, ip := range []string{"203.0.113.44", "203.0.113.45", "203.0.113.46"} {
		feedStalwart(d, stalwartLoginAndSend(587, ip, "user@example.com", "victim@example.org", "a@example.org")...)
	}
	if !hasRecentCompromisedFinding("example.com") || hasRecentCompromisedFinding("example.org") {
		t.Fatal("want the account's own domain marked, not the envelope sender's")
	}
}

func TestStalwartSessionJoinBounded(t *testing.T) {
	s := newStalwartSessions()
	now := stalwartTestStart
	for i := 0; i < 5000; i++ {
		s.remember(fmt.Sprintf("l587|203.0.113.%d|%d", i%250, i), "user@example.com", now)
	}
	if n := s.size(); n > stalwartSessionMax {
		t.Fatalf("size = %d, cap is %d", n, stalwartSessionMax)
	}
	s.remember("old", "user@example.com", now.Add(-61*time.Minute))
	if _, ok := s.account("old", now); ok {
		t.Fatal("a session older than an hour was returned")
	}
	s.remember("fresh", "user@example.com", now.Add(-59*time.Minute))
	if got, ok := s.account("fresh", now); !ok || got != "user@example.com" {
		t.Fatalf("fresh session = %q, %v", got, ok)
	}
}

// Only an SMTP send always follows a login on its own connection; a webmail
// send that does not join is not counted as unattributed.
func TestStalwartUnattributedCountsSMTPOnly(t *testing.T) {
	resetStalwartSendState(t)
	d, _ := newStalwartAuthDaemon(t, stalwartSendConfig())
	send := stalwartLoginAndSend(8080, "198.51.100.60", "user@example.com", "user@example.com", "a@example.org")[1]
	feedStalwart(d, send)
	if n := d.stalwart.stats.unattributed.Load(); n != 0 {
		t.Fatalf("unattributed = %d after an HTTP-listener send, want 0", n)
	}
}
