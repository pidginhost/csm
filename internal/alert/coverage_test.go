package alert

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// --- Severity.String unknown value --------------------------------------

func TestSeverityStringUnknown(t *testing.T) {
	if got := Severity(999).String(); got != "UNKNOWN" {
		t.Errorf("got %q, want UNKNOWN", got)
	}
}

// --- redactSensitive ---------------------------------------------------

func TestRedactSensitiveEmptyString(t *testing.T) {
	if got := redactSensitive(""); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestRedactSensitiveNoMatches(t *testing.T) {
	in := "plain log line with no secrets"
	if got := redactSensitive(in); got != in {
		t.Errorf("got %q, want unchanged", got)
	}
}

func TestRedactSensitivePassword(t *testing.T) {
	in := "POST /login password=s3cret&user=alice"
	got := redactSensitive(in)
	if strings.Contains(got, "s3cret") {
		t.Errorf("password leaked: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("redaction marker missing: %q", got)
	}
	if !strings.Contains(got, "user=alice") {
		t.Errorf("non-secret field was corrupted: %q", got)
	}
}

func TestRedactSensitiveMultiplePrefixes(t *testing.T) {
	in := "pass=aaa passwd=bbb new_password=ccc"
	got := redactSensitive(in)
	for _, secret := range []string{"aaa", "bbb", "ccc"} {
		if strings.Contains(got, secret) {
			t.Errorf("leaked secret %q in %q", secret, got)
		}
	}
}

func TestRedactSensitivePasswordFormEncoded(t *testing.T) {
	// The redactor is designed for URL/POST form data (`password=value`),
	// not JSON. Form-encoded keys stop at `&` or whitespace.
	in := `POST /login password=topsecret&other=ok`
	got := redactSensitive(in)
	if strings.Contains(got, "topsecret") {
		t.Errorf("password leaked: %q", got)
	}
	if !strings.Contains(got, "other=ok") {
		t.Errorf("non-secret field corrupted: %q", got)
	}
}

func TestRedactSensitiveCaseInsensitive(t *testing.T) {
	in := "POST Password=CaSeSeNsItIvE done"
	got := redactSensitive(in)
	if strings.Contains(got, "CaSeSeNsItIvE") {
		t.Errorf("case-insensitive redaction failed: %q", got)
	}
}

func TestRedactSensitiveMultipleOccurrencesOfSamePrefix(t *testing.T) {
	// Regression for the infinite-loop fix: two populated password=
	// pairs must both be redacted without hanging.
	in := "first password=aaa& then password=bbb done"
	got := redactSensitive(in)
	if strings.Contains(got, "aaa") {
		t.Errorf("first password leaked: %q", got)
	}
	if strings.Contains(got, "bbb") {
		t.Errorf("second password leaked: %q", got)
	}
	if strings.Count(got, "[REDACTED]") != 2 {
		t.Errorf("expected 2 [REDACTED] markers, got %q", got)
	}
}

func TestRedactSensitiveEmptyValueThenPopulated(t *testing.T) {
	// Regression for the empty-value search-advance fix: an empty
	// value first, then a populated one later, should still redact the
	// populated one instead of bailing out.
	in := "password=& then password=real-secret done"
	got := redactSensitive(in)
	if strings.Contains(got, "real-secret") {
		t.Errorf("later populated password not redacted: %q", got)
	}
}

func TestRedactSensitiveEmptyPasswordValueUnchanged(t *testing.T) {
	in := "password=&next=1"
	if got := redactSensitive(in); got != in {
		t.Errorf("empty-value-only case should return unchanged, got %q", got)
	}
}

func TestRedactSensitiveTokenValues(t *testing.T) {
	in := "token_value=abc123xyz stuff"
	got := redactSensitive(in)
	if strings.Contains(got, "abc123xyz") {
		t.Errorf("token leaked: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("redaction marker missing: %q", got)
	}
}

func TestRedactSensitiveAPIToken(t *testing.T) {
	in := "api_token=longerAPItoken123 next"
	got := redactSensitive(in)
	if strings.Contains(got, "longerAPItoken123") {
		t.Errorf("api token leaked: %q", got)
	}
}

// --- checkRateLimit ----------------------------------------------------

func TestCheckRateLimitAllowsUpToCap(t *testing.T) {
	dir := t.TempDir()
	// Reset any leftover ratelimit state from other tests.
	resetRateLimit(t, dir)

	for i := 0; i < 3; i++ {
		if !checkRateLimit(dir, 3) {
			t.Errorf("call %d should be allowed", i)
		}
	}
	if checkRateLimit(dir, 3) {
		t.Error("4th call within same hour should be rejected")
	}
}

func TestCheckRateLimitResetsOnNewHour(t *testing.T) {
	dir := t.TempDir()
	resetRateLimit(t, dir)

	// Seed a prior-hour state.
	prior := rateLimitState{
		Hour:  time.Now().Add(-2 * time.Hour).Format("2006-01-02T15"),
		Count: 100,
	}
	data, _ := json.Marshal(prior)
	if err := os.WriteFile(filepath.Join(dir, "ratelimit.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	// Next call should be allowed — new hour resets the counter.
	if !checkRateLimit(dir, 10) {
		t.Error("new-hour call should be allowed")
	}
}

func TestCheckRateLimitCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	resetRateLimit(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "ratelimit.json"), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	// Corrupt state should be treated as fresh.
	if !checkRateLimit(dir, 5) {
		t.Error("call with corrupt state should be allowed")
	}
}

// resetRateLimit wipes the ratelimit.json file and resets the package-level
// mutex so state from earlier tests doesn't leak in.
func resetRateLimit(t *testing.T, dir string) {
	t.Helper()
	_ = os.Remove(filepath.Join(dir, "ratelimit.json"))
}

// --- SendEmail ---------------------------------------------------------

func TestSendEmailRejectsNoRecipients(t *testing.T) {
	cfg := &config.Config{}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = "127.0.0.1:25"
	if err := SendEmail(cfg, "sub", "body"); err == nil {
		t.Fatal("empty To should error")
	}
}

func TestSendEmailDialFailureReturnsError(t *testing.T) {
	cfg := &config.Config{}
	cfg.Alerts.Email.To = []string{"a@b.test"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = "127.0.0.1:1" // nothing listens
	err := SendEmail(cfg, "sub", "body")
	if err == nil {
		t.Fatal("dial failure should error")
	}
	if !strings.Contains(err.Error(), "smtp dial") {
		t.Errorf("err = %v, want smtp dial ... prefix", err)
	}
}

func TestSendEmailFallbackDialSuccess(t *testing.T) {
	// Spin up a tiny TCP listener that speaks just enough SMTP to satisfy
	// smtp.SendMail's unauthenticated fallback path.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	done := make(chan struct{})
	go runFakeSMTP(t, ln, done)

	cfg := &config.Config{}
	cfg.Alerts.Email.To = []string{"to@example.com"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = ln.Addr().String()

	if err := SendEmail(cfg, "subject", "body"); err != nil {
		t.Fatalf("SendEmail: %v", err)
	}
	<-done
}

// runFakeSMTP accepts a single connection and mimics an open-relay SMTP
// server enough to satisfy smtp.SendMail's primary path. The Go smtp
// package tries EHLO then HELO then MAIL/RCPT/DATA/QUIT.
func runFakeSMTP(t *testing.T, ln net.Listener, done chan<- struct{}) {
	t.Helper()
	defer close(done)
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	write := func(s string) { _, _ = conn.Write([]byte(s)) }
	read := func() string {
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		return string(buf[:n])
	}

	write("220 fake SMTP ready\r\n")
	for i := 0; i < 20; i++ {
		line := read()
		if line == "" {
			return
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(lower, "ehlo"), strings.HasPrefix(lower, "helo"):
			write("250-fake\r\n250 OK\r\n")
		case strings.HasPrefix(lower, "mail from"), strings.HasPrefix(lower, "rcpt to"):
			write("250 OK\r\n")
		case strings.HasPrefix(lower, "data"):
			write("354 End data with <CR><LF>.<CR><LF>\r\n")
			// Consume until . on a line by itself.
			for j := 0; j < 10; j++ {
				part := read()
				if strings.Contains(part, "\r\n.\r\n") {
					break
				}
			}
			write("250 OK\r\n")
		case strings.HasPrefix(lower, "quit"):
			write("221 bye\r\n")
			return
		default:
			write("250 OK\r\n")
		}
	}
}

// --- SendWebhook -------------------------------------------------------

func TestSendWebhookRequiresURL(t *testing.T) {
	cfg := &config.Config{}
	if err := SendWebhook(cfg, "sub", "body"); err == nil {
		t.Fatal("empty URL should error")
	}
}

func TestSendWebhookGenericPayload(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.Type = ""

	if err := SendWebhook(cfg, "test subject", "test body"); err != nil {
		t.Fatal(err)
	}
	if got["subject"] != "test subject" {
		t.Errorf("subject = %q", got["subject"])
	}
	if got["body"] != "test body" {
		t.Errorf("body = %q", got["body"])
	}
}

func TestSendWebhookSlackPayload(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.Type = "slack"
	if err := SendWebhook(cfg, "subj", "body"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got["text"], "subj") {
		t.Errorf("slack text = %q", got["text"])
	}
}

func TestSendWebhookDiscordPayload(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.Alerts.Webhook.URL = srv.URL
	cfg.Alerts.Webhook.Type = "discord"
	if err := SendWebhook(cfg, "subj", "body"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got["content"], "subj") {
		t.Errorf("discord content = %q", got["content"])
	}
}

func TestSendWebhookNon200ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.Alerts.Webhook.URL = srv.URL
	err := SendWebhook(cfg, "sub", "body")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v, want 500", err)
	}
}

func TestSendWebhookDialFailure(t *testing.T) {
	cfg := &config.Config{}
	cfg.Alerts.Webhook.URL = "http://127.0.0.1:1/hook"
	if err := SendWebhook(cfg, "s", "b"); err == nil {
		t.Fatal("dial failure should error")
	}
}

// --- Dispatch ----------------------------------------------------------

func TestDispatchAllDisabledIsNoOp(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Email.Enabled = false
	cfg.Alerts.Webhook.Enabled = false
	if err := Dispatch(cfg, []Finding{{Check: "c", Message: "m", Severity: Critical}}); err != nil {
		t.Errorf("dispatch with nothing enabled = %v, want nil", err)
	}
}

func TestDispatchEmptyFindingsIsNoOp(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"to@example.test"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = "127.0.0.1:1"
	if err := Dispatch(cfg, nil); err != nil {
		t.Errorf("nil findings = %v, want nil", err)
	}
}

func TestDispatchSendsWebhook(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer srv.Close()

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = srv.URL

	err := Dispatch(cfg, []Finding{{Check: "c", Message: "m", Severity: Critical, Timestamp: time.Now()}})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !hit {
		t.Error("webhook handler was not invoked")
	}
}

func TestDispatchDedupes(t *testing.T) {
	var count int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		count++
		// The posted body must not contain the duplicated message twice
		// (we only care about this indirectly: Dispatch dedupes before
		// formatting, so only one unique finding should show up).
		if strings.Count(string(body), "dup-msg") < 1 {
			t.Errorf("webhook body missing finding: %s", body)
		}
	}))
	defer srv.Close()

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = srv.URL

	f := Finding{Check: "c", Message: "dup-msg", Severity: Critical, Timestamp: time.Now()}
	if err := Dispatch(cfg, []Finding{f, f, f}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if count != 1 {
		t.Errorf("webhook called %d times, want 1", count)
	}
}

func TestDispatchRateLimitsNonCritical(t *testing.T) {
	var count int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
	}))
	defer srv.Close()

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 2
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = srv.URL

	nonCritical := Finding{Check: "c", Message: "m", Severity: Warning, Timestamp: time.Now()}
	for i := 0; i < 5; i++ {
		// Each Dispatch with a unique message so Dedupe doesn't merge them.
		f := nonCritical
		f.Message = "m" + string(rune('0'+i))
		_ = Dispatch(cfg, []Finding{f})
	}
	if count != 2 {
		t.Errorf("webhook called %d times, want 2 (rate limit)", count)
	}
}

func TestDispatchCriticalAlwaysGoesThrough(t *testing.T) {
	var count int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
	}))
	defer srv.Close()

	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 1
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = srv.URL

	// First dispatch eats the entire hour budget.
	_ = Dispatch(cfg, []Finding{{Check: "a", Message: "a", Severity: Warning, Timestamp: time.Now()}})

	// Critical finding must still be delivered even with rate limit exhausted.
	crit := Finding{Check: "b", Message: "b", Severity: Critical, Timestamp: time.Now()}
	_ = Dispatch(cfg, []Finding{crit})

	if count != 2 {
		t.Errorf("webhook count = %d, want 2 (critical bypass)", count)
	}
}

func TestDispatchEmailErrorIsReturned(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir(), Hostname: "host"}
	cfg.Alerts.MaxPerHour = 10
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.To = []string{"a@b.test"}
	cfg.Alerts.Email.From = "csm@example.com"
	cfg.Alerts.Email.SMTP = "127.0.0.1:1" // unreachable
	err := Dispatch(cfg, []Finding{{Check: "c", Message: "m", Severity: Critical, Timestamp: time.Now()}})
	if err == nil {
		t.Fatal("unreachable SMTP should propagate error")
	}
	if !strings.Contains(err.Error(), "email:") {
		t.Errorf("err = %v, want 'email:' prefix", err)
	}
}

// --- SendHeartbeat -----------------------------------------------------

func TestSendHeartbeatDisabledIsNoOp(t *testing.T) {
	cfg := &config.Config{}
	cfg.Alerts.Heartbeat.Enabled = false
	cfg.Alerts.Heartbeat.URL = "http://127.0.0.1:1/hb"
	SendHeartbeat(cfg) // must not touch the network
}

func TestSendHeartbeatEmptyURLIsNoOp(t *testing.T) {
	cfg := &config.Config{}
	cfg.Alerts.Heartbeat.Enabled = true
	cfg.Alerts.Heartbeat.URL = ""
	SendHeartbeat(cfg)
}

func TestSendHeartbeatHitsURL(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer srv.Close()

	cfg := &config.Config{}
	cfg.Alerts.Heartbeat.Enabled = true
	cfg.Alerts.Heartbeat.URL = srv.URL
	SendHeartbeat(cfg)
	if !hit {
		t.Error("heartbeat URL was not hit")
	}
}

func TestSendHeartbeatHTTPErrorIsSwallowed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Alerts.Heartbeat.Enabled = true
	cfg.Alerts.Heartbeat.URL = "http://127.0.0.1:1/hb"
	// Must not panic / hang / return anything observable.
	SendHeartbeat(cfg)
}

// --- FilterBlockedAlerts / loadBlockedIPs / loadPendingIPs ------------

func TestFilterBlockedAlertsDisabledPassesThrough(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = false
	findings := []Finding{{Check: "ip_reputation", Message: "1.2.3.4 flagged"}}
	if got := FilterBlockedAlerts(cfg, findings); len(got) != 1 {
		t.Errorf("disabled filter should pass through, got %d", len(got))
	}
}

func TestFilterBlockedAlertsAutoResponseSkipsReputationFindings(t *testing.T) {
	// FilterBlockedAlerts returns early when the blocked-IP set is
	// empty. Seed one so the function reaches the per-finding filter
	// loop where the AutoResponse branch lives.
	dir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(dir, "blocked_ips.json"),
		[]byte(`{"ips":[{"ip":"99.99.99.99","expires_at":"2099-01-01T00:00:00Z"}]}`),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{StatePath: dir}
	cfg.Suppressions.SuppressBlockedAlerts = true
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	findings := []Finding{
		{Check: "ip_reputation", Message: "1.2.3.4 flagged", Severity: Warning},
		{Check: "malware", Message: "shell.php", Severity: Critical},
	}
	got := FilterBlockedAlerts(cfg, findings)
	if len(got) != 1 || got[0].Check != "malware" {
		t.Errorf("got %+v, want only [malware]", got)
	}
}

func TestFilterBlockedAlertsSkipsAutoBlockCheck(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = true
	findings := []Finding{
		{Check: "auto_block", Message: "AUTO-BLOCK: 1.2.3.4"},
		{Check: "other", Message: "keep me"},
	}
	got := FilterBlockedAlerts(cfg, findings)
	if len(got) != 1 || got[0].Check != "other" {
		t.Errorf("got %+v, want only [other]", got)
	}
}

func TestFilterBlockedAlertsWithKnownBlockedIP(t *testing.T) {
	dir := t.TempDir()
	// Seed blocked_ips.json.
	body := `{"ips":[{"ip":"5.5.5.5","expires_at":"2099-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(dir, "blocked_ips.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{StatePath: dir}
	cfg.Suppressions.SuppressBlockedAlerts = true
	findings := []Finding{
		{Check: "ip_reputation", Message: "ip=5.5.5.5 flagged"},
		{Check: "ip_reputation", Message: "ip=6.6.6.6 flagged"}, // not blocked
	}
	got := FilterBlockedAlerts(cfg, findings)
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Message, "6.6.6.6") {
		t.Errorf("wrong finding kept: %+v", got[0])
	}
}

func TestLoadBlockedIPsSkipsExpired(t *testing.T) {
	dir := t.TempDir()
	body := `{"ips":[
		{"ip":"1.1.1.1","expires_at":"2099-01-01T00:00:00Z"},
		{"ip":"2.2.2.2","expires_at":"2000-01-01T00:00:00Z"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "blocked_ips.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	ips := loadBlockedIPs(dir)
	if !ips["1.1.1.1"] {
		t.Error("1.1.1.1 should be loaded")
	}
	if ips["2.2.2.2"] {
		t.Error("2.2.2.2 is expired, should be skipped")
	}
}

func TestLoadBlockedIPsInjectedFunc(t *testing.T) {
	orig := BlockedIPsFunc
	BlockedIPsFunc = func() map[string]bool {
		return map[string]bool{"9.9.9.9": true}
	}
	t.Cleanup(func() { BlockedIPsFunc = orig })

	ips := loadBlockedIPs(t.TempDir())
	if !ips["9.9.9.9"] {
		t.Error("injected BlockedIPsFunc should take precedence")
	}
}

func TestLoadBlockedIPsFirewallStateFlatFile(t *testing.T) {
	orig := BlockedIPsFunc
	BlockedIPsFunc = nil
	t.Cleanup(func() { BlockedIPsFunc = orig })

	dir := t.TempDir()
	fwDir := filepath.Join(dir, "firewall")
	if err := os.MkdirAll(fwDir, 0700); err != nil {
		t.Fatal(err)
	}
	body := `{"blocked":[{"ip":"7.7.7.7","expires_at":"2099-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(fwDir, "state.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	ips := loadBlockedIPs(dir)
	if !ips["7.7.7.7"] {
		t.Errorf("should load from firewall state.json: %v", ips)
	}
}

func TestLoadBlockedIPsMalformed(t *testing.T) {
	orig := BlockedIPsFunc
	BlockedIPsFunc = nil
	t.Cleanup(func() { BlockedIPsFunc = orig })

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "blocked_ips.json"), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	ips := loadBlockedIPs(dir)
	if len(ips) != 0 {
		t.Errorf("malformed file should yield empty, got %v", ips)
	}
}

func TestLoadPendingIPs(t *testing.T) {
	dir := t.TempDir()
	body := `{"pending":[{"ip":"3.3.3.3"},{"ip":"4.4.4.4"}]}`
	if err := os.WriteFile(filepath.Join(dir, "blocked_ips.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	got := loadPendingIPs(dir)
	if !got["3.3.3.3"] || !got["4.4.4.4"] {
		t.Errorf("loadPendingIPs = %v, want [3.3.3.3, 4.4.4.4]", got)
	}
}

func TestLoadPendingIPsMissing(t *testing.T) {
	got := loadPendingIPs(t.TempDir())
	if len(got) != 0 {
		t.Errorf("missing file should yield empty, got %v", got)
	}
}

func TestFilterBlockedAlertsPendingIPsSuppressed(t *testing.T) {
	orig := BlockedIPsFunc
	BlockedIPsFunc = nil
	t.Cleanup(func() { BlockedIPsFunc = orig })

	dir := t.TempDir()
	body := `{"pending":[{"ip":"8.8.8.8"}]}`
	if err := os.WriteFile(filepath.Join(dir, "blocked_ips.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{StatePath: dir}
	cfg.Suppressions.SuppressBlockedAlerts = true
	findings := []Finding{{Check: "ip_reputation", Message: "8.8.8.8 scanning"}}
	got := FilterBlockedAlerts(cfg, findings)
	if len(got) != 0 {
		t.Errorf("pending IP should be suppressed, got %v", got)
	}
}

func TestFilterBlockedAlertsLearnsFromAutoBlockBatch(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = true

	findings := []Finding{
		{Check: "auto_block", Message: "AUTO-BLOCK: 9.9.9.9 brute force"},
		{Check: "ip_reputation", Message: "9.9.9.9 was flagged"},
	}
	got := FilterBlockedAlerts(cfg, findings)
	// Both should be dropped: auto_block by check name, reputation by
	// the learned-in-batch blocked set.
	if len(got) != 0 {
		t.Errorf("got %v, want empty (auto-block learned)", got)
	}
}

func TestFilter_SubnetBlockSuppressesReputationInSameBatch(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	cfg.Suppressions.SuppressBlockedAlerts = true

	findings := []Finding{
		{
			Severity: Critical,
			Check:    "auto_block",
			Message:  "AUTO-BLOCK-SUBNET: 203.0.113.0/24 blocked",
		},
		{
			Severity: Warning,
			Check:    "ip_reputation",
			Message:  "Known malicious IP accessing server: 203.0.113.42 (from abuseipdb)",
		},
		{
			Severity: Warning,
			Check:    "ip_reputation",
			Message:  "Known malicious IP accessing server: 10.20.30.40 (from abuseipdb)",
		},
	}

	got := FilterBlockedAlerts(cfg, findings)

	// The ip_reputation finding for 203.0.113.42 must be suppressed because
	// it is inside the just-blocked /24. The finding for 10.20.30.40 must
	// pass through (different subnet).
	for _, f := range got {
		if f.Check == "ip_reputation" && strings.Contains(f.Message, "203.0.113.42") {
			t.Errorf("ip_reputation for 203.0.113.42 should be suppressed by subnet block; got %v", f)
		}
	}
	var kept bool
	for _, f := range got {
		if f.Check == "ip_reputation" && strings.Contains(f.Message, "10.20.30.40") {
			kept = true
		}
	}
	if !kept {
		t.Errorf("ip_reputation for 10.20.30.40 must not be suppressed (outside blocked /24)")
	}
}

// --- httpClient helper ------------------------------------------------

func TestHttpClientTimeoutApplied(t *testing.T) {
	c := httpClient(3 * time.Second)
	if c.Timeout != 3*time.Second {
		t.Errorf("Timeout = %v, want 3s", c.Timeout)
	}
}
