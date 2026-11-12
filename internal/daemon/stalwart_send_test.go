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

// Sites send through a loopback listener, and webmail sends through the HTTP
// listener: both count toward volume and recipients only.
func TestStalwartLocalSubmissionVolumeOnly(t *testing.T) {
	for _, tc := range []struct {
		port int
		ip   string
	}{{10465, "127.0.0.1"}, {8080, "198.51.100.50"}} {
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

func TestStalwartBareAccountCorrelatesFromDomain(t *testing.T) {
	resetStalwartSendState(t)
	stubStalwartPTR(t, "mail.example.net")
	stubGeo(t, map[string]string{"203.0.113.44": "DE", "203.0.113.45": "FR", "203.0.113.46": "BR"})
	calls := stubMailboxActions(t, func([]string) ([]byte, error) { return uapiOK() })
	d, _ := newStalwartAuthDaemon(t, stalwartSendConfig())
	var got []alert.Finding
	for _, ip := range []string{"203.0.113.44", "203.0.113.45", "203.0.113.46"} {
		got = append(got, feedStalwart(d, stalwartLoginAndSend(587, ip, "john", "john@example.com", "a@example.org")...)...)
	}
	sender := findingsOf(got, "email_compromised_account")
	if len(sender) != 1 || sender[0].Severity != alert.Critical {
		t.Fatalf("findings = %+v, want one Critical sender finding", got)
	}
	if sender[0].Context != stalwartNoSuspendContext {
		t.Fatalf("context = %q", sender[0].Context)
	}
	if !hasRecentCompromisedFinding("example.com") {
		t.Fatal("the sender address's domain must be marked for correlation")
	}
	if len(*calls) != 0 {
		t.Fatalf("suspension attempted: %v", *calls)
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
