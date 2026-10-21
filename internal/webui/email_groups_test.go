package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// Helper: build a finding with the email-relevant identity fields.
func emailFinding(check string, sev alert.Severity, mailbox, domain, ip string, ts time.Time) alert.Finding {
	return alert.Finding{
		Severity:  sev,
		Check:     check,
		Message:   check + " event",
		Mailbox:   mailbox,
		Domain:    domain,
		SourceIP:  ip,
		Timestamp: ts,
	}
}

func TestEmailGroupsAuthFailureMergesByMailbox(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "example.com", "192.0.2.1", now.Add(-3*time.Minute)),
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "example.com", "192.0.2.2", now.Add(-2*time.Minute)),
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "example.com", "192.0.2.1", now.Add(-1*time.Minute)),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "")
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1: %+v", len(groups), groups)
	}
	g := groups[0]
	if g.Kind != "auth_failure" {
		t.Errorf("kind = %q, want auth_failure", g.Kind)
	}
	if g.Title != "jane@example.com" {
		t.Errorf("title = %q, want mailbox", g.Title)
	}
	if g.Count != 3 {
		t.Errorf("count = %d, want 3", g.Count)
	}
	if len(g.IPs) != 2 {
		t.Errorf("ips = %v, want 2 unique", g.IPs)
	}
	if g.Subject != "mailbox" {
		t.Errorf("subject = %q, want mailbox", g.Subject)
	}
}

func TestEmailGroupsAuthFailureFallsBackToSourceIP(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.High, "", "", "203.0.113.10", now.Add(-2*time.Minute)),
		emailFinding("email_auth_failure_realtime", alert.High, "", "", "203.0.113.10", now.Add(-1*time.Minute)),
		emailFinding("email_auth_failure_realtime", alert.High, "", "", "203.0.113.20", now),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "")
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2 (one per IP): %+v", len(groups), groups)
	}
	for _, g := range groups {
		if g.Subject != "ip" {
			t.Errorf("subject = %q, want ip when mailbox is absent", g.Subject)
		}
	}
}

func TestEmailGroupsSpamOutbreakDedupesUnknownMailbox(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("email_spam_outbreak", alert.Critical, "", "example.com", "", now.Add(-3*time.Minute)),
		emailFinding("email_spam_outbreak", alert.Critical, "", "example.com", "", now.Add(-2*time.Minute)),
		emailFinding("email_spam_outbreak", alert.Critical, "", "example.com", "", now.Add(-1*time.Minute)),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "")
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1 (deduped): %+v", len(groups), groups)
	}
	if groups[0].Count != 3 {
		t.Errorf("count = %d, want 3", groups[0].Count)
	}
}

func TestEmailGroupsKindFilterScopesResults(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.High, "a@example.com", "", "192.0.2.1", now),
		emailFinding("email_compromised_account", alert.Critical, "b@example.com", "", "", now),
		emailFinding("email_spam_outbreak", alert.Critical, "c@example.com", "", "", now),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "auth_failure")
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1 auth_failure", len(groups))
	}
	if groups[0].Kind != "auth_failure" {
		t.Errorf("kind = %q, want auth_failure", groups[0].Kind)
	}
}

func TestEmailGroupsRespectsDateRange(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		// Outside the requested window: too old.
		emailFinding("email_auth_failure_realtime", alert.High, "old@example.com", "", "192.0.2.1", now.Add(-25*time.Hour)),
		// In window.
		emailFinding("email_auth_failure_realtime", alert.High, "new@example.com", "", "192.0.2.2", now.Add(-1*time.Hour)),
	}
	groups := buildEmailGroups(in, now.Add(-12*time.Hour), now, "")
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1 (window filter)", len(groups))
	}
	if groups[0].Title != "new@example.com" {
		t.Errorf("title = %q, want new@example.com", groups[0].Title)
	}
}

func TestEmailGroupsIgnoresNonEmailFindings(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("webshell", alert.Critical, "", "", "", now),
		emailFinding("waf_status", alert.Warning, "", "", "", now),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "")
	if len(groups) != 0 {
		t.Fatalf("got %d groups, want 0 for non-email checks: %+v", len(groups), groups)
	}
}

func TestEmailGroupsSortsBySeverityThenLastSeen(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.Warning, "low@example.com", "", "192.0.2.1", now),
		emailFinding("email_compromised_account", alert.Critical, "crit@example.com", "", "", now.Add(-30*time.Minute)),
		emailFinding("email_compromised_account", alert.Critical, "newer@example.com", "", "", now),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "")
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(groups))
	}
	if groups[0].Severity != "CRITICAL" {
		t.Errorf("first group severity = %s, want critical", groups[0].Severity)
	}
	if groups[0].Title != "newer@example.com" {
		t.Errorf("first crit group should be newest: got %q", groups[0].Title)
	}
	if groups[2].Severity != "WARNING" {
		t.Errorf("last group severity = %s, want warning", groups[2].Severity)
	}
}

func TestEmailGroupsAggregatesQueueAlerts(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("mail_queue", alert.High, "", "", "", now.Add(-3*time.Minute)),
		emailFinding("mail_queue", alert.High, "", "", "", now.Add(-2*time.Minute)),
		emailFinding("mail_per_account", alert.Warning, "noisy@example.com", "", "", now.Add(-1*time.Minute)),
	}
	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "queue_alert")
	if len(groups) != 2 {
		t.Fatalf("got %d queue groups, want 2 (mail_queue + mail_per_account)", len(groups))
	}
}

func TestEmailGroupsIncludesCurrentEmailDetectorChecks(t *testing.T) {
	now := time.Now()
	cases := []struct {
		check string
		kind  string
	}{
		{check: "exim_frozen_realtime", kind: "queue_alert"},
		{check: "mail_queue_unavailable", kind: "queue_alert"},
		{check: "email_av_degraded", kind: "malware"},
		{check: "email_av_timeout", kind: "malware"},
		{check: "email_av_parse_error", kind: "malware"},
		{check: "email_av_quarantine_error", kind: "malware"},
		{check: "mail_bruteforce", kind: "auth_failure"},
		{check: "mail_bruteforce_suspected", kind: "auth_failure"},
		{check: "smtp_bruteforce", kind: "auth_failure"},
		{check: "smtp_probe_abuse", kind: "auth_failure"},
		{check: "mail_account_compromised", kind: "compromised_account"},
		{check: "email_suspicious_forwarder", kind: "compromised_account"},
		{check: "email_rate_critical", kind: "spam_outbreak"},
	}

	for _, tc := range cases {
		t.Run(tc.check, func(t *testing.T) {
			groups := buildEmailGroups(
				[]alert.Finding{emailFinding(tc.check, alert.High, "user@example.com", "example.com", "192.0.2.10", now)},
				now.Add(-1*time.Hour),
				now,
				"",
			)
			if len(groups) != 1 {
				t.Fatalf("got %d groups, want 1 for %s", len(groups), tc.check)
			}
			if groups[0].Kind != tc.kind {
				t.Fatalf("kind = %q, want %q", groups[0].Kind, tc.kind)
			}
		})
	}
}

func TestEmailGroupsEmptyInput(t *testing.T) {
	groups := buildEmailGroups(nil, time.Time{}, time.Now(), "")
	if len(groups) != 0 {
		t.Fatalf("nil input should produce no groups, got %d", len(groups))
	}
}

func TestAPIEmailGroupsRejectsNonGet(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	s.apiEmailGroups(w, httptest.NewRequest(http.MethodPost, "/api/v1/email/groups", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestAPIEmailGroupsReturnsJSON(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "", "192.0.2.5", now.Add(-1*time.Minute)),
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "", "192.0.2.6", now),
	})

	w := httptest.NewRecorder()
	s.apiEmailGroups(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/groups", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}

	var resp emailGroupsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	if len(resp.Groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(resp.Groups))
	}
	if resp.Groups[0].Title != "jane@example.com" {
		t.Errorf("title = %q", resp.Groups[0].Title)
	}
	if resp.Groups[0].Count != 2 {
		t.Errorf("count = %d, want 2", resp.Groups[0].Count)
	}
}

func TestAPIEmailGroupsDateOnlyToIncludesWholeDay(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	day := time.Now().AddDate(0, 0, -1)
	ts := time.Date(day.Year(), day.Month(), day.Day(), 15, 30, 0, 0, time.Local)
	s.store.AppendHistory([]alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.High, "same-day@example.com", "", "192.0.2.8", ts),
	})

	date := ts.Format("2006-01-02")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/email/groups?from="+date+"&to="+date, nil)
	s.apiEmailGroups(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp emailGroupsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	if len(resp.Groups) != 1 {
		t.Fatalf("groups = %d, want 1 for date-only same-day range: %+v", len(resp.Groups), resp.Groups)
	}
	if resp.Groups[0].Title != "same-day@example.com" {
		t.Errorf("title = %q, want same-day@example.com", resp.Groups[0].Title)
	}
}

func TestAPIEmailGroupsReadScopeAccess(t *testing.T) {
	s := newTestServerWithBbolt(t, "admin-tok")
	s.cfg.WebUI.Tokens = []config.WebUIToken{
		{Name: "admin", Token: "admin-tok", Scope: "admin", IssuedAt: time.Now().UTC().Format(time.RFC3339)},
		{Name: "read-only", Token: "read-tok", Scope: "read", IssuedAt: time.Now().UTC().Format(time.RFC3339)},
	}

	now := time.Now()
	s.store.AppendHistory([]alert.Finding{
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "", "192.0.2.7", now),
	})

	handler := s.requireRead(http.HandlerFunc(s.apiEmailGroups))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/email/groups", nil)
	req.Header.Set("Authorization", "Bearer read-tok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("read-scope GET status = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestEmailGroupsSortByCountWithinSeverity(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		// one HIGH group with a single, most-recent event
		emailFinding("email_auth_failure_realtime", alert.High, "solo@example.com", "example.com", "192.0.2.1", now),
	}
	// a HIGH group with many (older) events
	for i := 0; i < 50; i++ {
		in = append(in, emailFinding("email_auth_failure_realtime", alert.High, "busy@example.com", "example.com",
			"192.0.2."+itoa(10+i), now.Add(-10*time.Minute)))
	}
	// a HIGH group with a middling count
	for i := 0; i < 5; i++ {
		in = append(in, emailFinding("email_auth_failure_realtime", alert.High, "mid@example.com", "example.com",
			"198.51.100."+itoa(10+i), now.Add(-5*time.Minute)))
	}
	// a CRITICAL group with a single event must still outrank all HIGH groups
	in = append(in, emailFinding("email_compromised_account", alert.Critical, "owned@example.com", "example.com", "203.0.113.9", now.Add(-30*time.Minute)))

	groups := buildEmailGroups(in, now.Add(-1*time.Hour), now, "")
	if len(groups) != 4 {
		t.Fatalf("got %d groups, want 4", len(groups))
	}
	if groups[0].Severity != "CRITICAL" {
		t.Errorf("group[0] severity = %s, want critical first", groups[0].Severity)
	}
	gotCounts := []int{groups[1].Count, groups[2].Count, groups[3].Count}
	wantCounts := []int{50, 5, 1}
	for i := range wantCounts {
		if gotCounts[i] != wantCounts[i] {
			t.Errorf("HIGH group order by count: got %v, want %v", gotCounts, wantCounts)
			break
		}
	}
}

func writeFirewallState(t *testing.T, statePath string, st firewall.FirewallState) {
	t.Helper()
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(statePath, "firewall"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statePath, "firewall", "state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEmailGroupHandledNeedsEveryIPBlocked(t *testing.T) {
	ips := map[netip.Addr]bool{netip.MustParseAddr("203.0.113.5"): true}
	nets := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	groups := []emailGroup{
		{Title: "all", Kind: "auth_failure", IPs: []string{"203.0.113.5", "198.51.100.7"}},
		{Title: "some", Kind: "auth_failure", IPs: []string{"203.0.113.5", "192.0.2.1"}},
		{Title: "mapped", Kind: "auth_failure", IPs: []string{"::ffff:203.0.113.5"}},
		{Title: "noip", Kind: "compromised_account"},
		{Title: "junk", Kind: "auth_failure", IPs: []string{"not-an-ip"}},
	}
	annotateEmailGroups(groups, ips, nets)
	want := map[string][2]any{"all": {"all", true}, "some": {"some", false}, "mapped": {"all", true},
		"noip": {"no_ip", false}, "junk": {"none", false}}
	for _, g := range groups {
		if w := want[g.Title]; g.BlockState != w[0] || g.Handled != w[1] {
			t.Errorf("%s: %s %v", g.Title, g.BlockState, g.Handled)
		}
	}
}

// A blocked source IP ends an auth attack, not a compromised password or a
// spam run: only auth failures whose every finding names its attacker can
// be handled.
func TestEmailGroupHandledOnlyForAddressedAuthFailures(t *testing.T) {
	now := time.Now()
	in := []alert.Finding{
		emailFinding("mail_account_compromised", alert.Critical, "owned@example.com", "", "203.0.113.5", now),
		emailFinding("email_cloud_relay_abuse", alert.High, "relay@example.com", "", "203.0.113.5", now),
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "", "203.0.113.5", now),
		emailFinding("email_auth_failure_realtime", alert.High, "jane@example.com", "", "", now),
		emailFinding("email_auth_failure_realtime", alert.High, "bob@example.com", "", "203.0.113.5", now),
	}
	groups := buildEmailGroups(in, now.Add(-time.Hour), now, "")
	annotateEmailGroups(groups, map[netip.Addr]bool{netip.MustParseAddr("203.0.113.5"): true}, nil)
	want := map[string][2]any{
		"owned@example.com": {"all", false},
		"relay@example.com": {"all", false},
		"jane@example.com":  {"all", false},
		"bob@example.com":   {"all", true},
	}
	if len(groups) != len(want) {
		t.Fatalf("got %d groups, want %d: %+v", len(groups), len(want), groups)
	}
	for _, g := range groups {
		if w := want[g.Title]; g.BlockState != w[0] || g.Handled != w[1] {
			t.Errorf("%s (%s): %s %v, want %v", g.Title, g.Kind, g.BlockState, g.Handled, w)
		}
	}
}

// A subnet spray names its subnet. A block covers it only when the block's
// prefix holds the whole subnet.
func TestEmailGroupSubnetSprayCoveredBySubnetBlock(t *testing.T) {
	now := time.Now()
	spray := alert.Finding{Severity: alert.High, Check: "mail_subnet_spray", Message: "spray",
		CIDRs: []string{"198.51.100.0/24"}, Timestamp: now}
	for _, tc := range []struct {
		block   string
		state   string
		handled bool
	}{
		{"198.51.100.0/24", "all", true},
		{"198.51.0.0/16", "all", true},
		{"198.51.100.0/28", "none", false},
		{"203.0.113.0/24", "none", false},
	} {
		groups := buildEmailGroups([]alert.Finding{spray}, now.Add(-time.Hour), now, "")
		if len(groups) != 1 || len(groups[0].IPs) != 1 || groups[0].IPs[0] != "198.51.100.0/24" {
			t.Fatalf("spray groups = %+v, want one group naming its subnet", groups)
		}
		annotateEmailGroups(groups, nil, []netip.Prefix{netip.MustParsePrefix(tc.block)})
		if g := groups[0]; g.BlockState != tc.state || g.Handled != tc.handled {
			t.Errorf("block %s: %s %v, want %s %v", tc.block, g.BlockState, g.Handled, tc.state, tc.handled)
		}
	}
}

func TestActiveBlocksIgnoresDryRunExpiredUnverified(t *testing.T) {
	loadedAt := time.Now()
	// The request clock runs an hour ahead of the file read, so a block
	// LoadState still holds can have lapsed by the request's now.
	now := loadedAt.Add(time.Hour)
	dir := t.TempDir()

	ips, nets, err := activeBlocks(dir, now)
	if err != nil || len(ips) != 0 || len(nets) != 0 {
		t.Fatalf("no state file: %v %v %v, want nothing blocked and no error", ips, nets, err)
	}

	// A dry-run block is recorded in the store next to the firewall state,
	// never in it.
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.RecordDryRunBlock("203.0.113.9", "SMTP AUTH brute force", time.Hour)
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	writeFirewallState(t, dir, firewall.FirewallState{
		Blocked: []firewall.BlockedEntry{
			{IP: "203.0.113.1", Reason: "smtp probe", ExpiresAt: now.Add(time.Hour)},
			{IP: "203.0.113.2", Reason: "spam source"},
			{IP: "203.0.113.3", Reason: "mail flood", ExpiresAt: loadedAt.Add(30 * time.Minute)},
			{IP: "203.0.113.4", Reason: "smtp probe", Unverified: true},
			{IP: "::ffff:203.0.113.5", Reason: "spam source"},
			{IP: "not-an-ip", Reason: "spam source"},
		},
		BlockedNet: []firewall.SubnetEntry{
			{CIDR: "192.0.2.0/24", Reason: "mail spray"},
			{CIDR: "198.51.100.0/24", Reason: "mail spray", ExpiresAt: loadedAt.Add(30 * time.Minute)},
			{CIDR: "2001:db8::/32", Reason: "mail spray", ExpiresAt: now.Add(time.Hour)},
			{CIDR: "junk", Reason: "mail spray"},
		},
	})

	ips, nets, err = activeBlocks(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	wantIPs := map[netip.Addr]bool{
		netip.MustParseAddr("203.0.113.1"): true,
		netip.MustParseAddr("203.0.113.2"): true,
		netip.MustParseAddr("203.0.113.5"): true,
	}
	if len(ips) != len(wantIPs) {
		t.Errorf("ips = %v, want %v", ips, wantIPs)
	}
	for ip := range wantIPs {
		if !ips[ip] {
			t.Errorf("ips = %v, missing %s", ips, ip)
		}
	}
	if ips[netip.MustParseAddr("203.0.113.9")] {
		t.Error("a dry-run block counted as enforced")
	}
	wantNets := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	if !slices.Equal(nets, wantNets) {
		t.Errorf("nets = %v, want %v", nets, wantNets)
	}

	writeCorruptFirewallState(t, dir)
	if _, _, err := activeBlocks(dir, now); err == nil {
		t.Error("unreadable state read as nothing blocked")
	}
}

func getEmailGroups(t *testing.T, s *Server, query string) emailGroupsResponse {
	t.Helper()
	w := httptest.NewRecorder()
	s.apiEmailGroups(w, httptest.NewRequest(http.MethodGet, "/api/v1/email/groups"+query, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var resp emailGroupsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	return resp
}

func groupTitles(groups []emailGroup) []string {
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = g.Title
	}
	return out
}

func TestEmailGroupsUnhandledFirstThenLimit(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now()
	var in []alert.Finding
	for i := 0; i < 3; i++ {
		in = append(in, emailFinding("email_auth_failure_realtime", alert.High, "a@example.com", "", "203.0.113.1", now.Add(-time.Minute)))
	}
	for i := 0; i < 2; i++ {
		in = append(in, emailFinding("email_auth_failure_realtime", alert.High, "b@example.com", "", "198.51.100.7", now.Add(-time.Minute)))
	}
	in = append(in, emailFinding("email_auth_failure_realtime", alert.High, "c@example.com", "", "192.0.2.9", now.Add(-time.Minute)))
	s.store.AppendHistory(in)
	writeFirewallState(t, s.cfg.StatePath, firewall.FirewallState{
		Blocked:    []firewall.BlockedEntry{{IP: "203.0.113.1", Reason: "SMTP AUTH brute force"}},
		BlockedNet: []firewall.SubnetEntry{{CIDR: "198.51.100.0/24", Reason: "mail spray"}},
	})

	resp := getEmailGroups(t, s, "?limit=2")
	if got := groupTitles(resp.Groups); !slices.Equal(got, []string{"c@example.com", "a@example.com"}) {
		t.Fatalf("items = %v, want the unhandled group first, then the limit", got)
	}
	if g := resp.Groups[0]; g.Handled || g.BlockState != "none" {
		t.Errorf("unhandled group: %s %v", g.BlockState, g.Handled)
	}
	if g := resp.Groups[1]; !g.Handled || g.BlockState != "all" {
		t.Errorf("handled group: %s %v", g.BlockState, g.Handled)
	}
	if resp.HandledCount != 2 || resp.Total != 3 || !resp.Truncated || resp.BlocksUnavailable {
		t.Errorf("handled_count %d total %d truncated %v unavailable %v, want 2, 3, true, false",
			resp.HandledCount, resp.Total, resp.Truncated, resp.BlocksUnavailable)
	}

	// Block state changes while history does not: the memoised groups are
	// annotated again, in their original order.
	writeFirewallState(t, s.cfg.StatePath, firewall.FirewallState{
		BlockedNet: []firewall.SubnetEntry{{CIDR: "198.51.100.0/24", Reason: "mail spray"}},
	})
	resp = getEmailGroups(t, s, "?limit=2")
	if got := groupTitles(resp.Groups); !slices.Equal(got, []string{"a@example.com", "c@example.com"}) {
		t.Fatalf("after unblock items = %v, want both unhandled groups in severity and count order", got)
	}
	if resp.HandledCount != 1 {
		t.Errorf("after unblock handled_count = %d, want 1", resp.HandledCount)
	}

	// An unreadable firewall state hides nothing.
	writeCorruptFirewallState(t, s.cfg.StatePath)
	resp = getEmailGroups(t, s, "")
	if !resp.BlocksUnavailable || resp.HandledCount != 0 || len(resp.Groups) != 3 {
		t.Fatalf("unreadable state: unavailable %v handled_count %d items %d, want true, 0, 3",
			resp.BlocksUnavailable, resp.HandledCount, len(resp.Groups))
	}
	for _, g := range resp.Groups {
		if g.Handled || g.BlockState != "" {
			t.Errorf("%s: %q %v, want no block state when it cannot be read", g.Title, g.BlockState, g.Handled)
		}
	}
}

// The omitted tail can contain an unblocked attacker or an addressless
// finding for any returned group. A partial scan cannot prove handling.
func TestEmailGroupsTruncatedHistoryIsNotHandled(t *testing.T) {
	for _, attacker := range []string{"198.51.100.8", ""} {
		t.Run("older attacker="+attacker, func(t *testing.T) {
			s := newTestServerWithBbolt(t, "tok")
			now := time.Now().Add(-time.Minute)
			findings := []alert.Finding{emailFinding("mail_bruteforce", alert.High, "user@example.com", "", attacker, now.Add(-time.Hour))}
			for i := 0; i < emailGroupsScanCap; i++ {
				findings = append(findings, emailFinding("mail_bruteforce", alert.High, "user@example.com", "", "203.0.113.7", now))
			}
			s.store.AppendHistory(findings)
			writeFirewallState(t, s.cfg.StatePath, firewall.FirewallState{Blocked: []firewall.BlockedEntry{{IP: "203.0.113.7"}}})

			resp := getEmailGroups(t, s, "")
			if !resp.Truncated || resp.Scanned != emailGroupsScanCap || len(resp.Groups) != 1 {
				t.Fatalf("expected one partially scanned group: %+v", resp)
			}
			if resp.Groups[0].Handled || resp.HandledCount != 0 {
				t.Fatalf("incomplete attacker history marked handled: %+v", resp)
			}
		})
	}
}

func TestEmailGroupsStaleHistoryIsNotHandled(t *testing.T) {
	withMemoAges(t, time.Hour, time.Hour)
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now().Add(-time.Minute)
	s.store.AppendHistory([]alert.Finding{emailFinding("mail_bruteforce", alert.High, "user@example.com", "", "203.0.113.7", now)})
	writeFirewallState(t, s.cfg.StatePath, firewall.FirewallState{Blocked: []firewall.BlockedEntry{{IP: "203.0.113.7"}}})
	if resp := getEmailGroups(t, s, ""); len(resp.Groups) != 1 || !resp.Groups[0].Handled || resp.HandledCount != 1 {
		t.Fatalf("complete history should be handled: %+v", resp)
	}
	// A new unblocked attacker inside the memo window shows on the next
	// request rather than hiding behind the throttled result.
	s.store.AppendHistory([]alert.Finding{emailFinding("mail_bruteforce", alert.High, "user@example.com", "", "198.51.100.8", now.Add(time.Second))})
	resp := getEmailGroups(t, s, "")
	if len(resp.Groups) != 1 || resp.Groups[0].Count != 2 || resp.Groups[0].BlockState != "some" {
		t.Fatalf("expected the group with the new attacker: %+v", resp)
	}
	if resp.Groups[0].Handled || resp.HandledCount != 0 {
		t.Fatalf("group with an unblocked attacker marked handled: %+v", resp)
	}
}

// A result built from history older than the current mark can miss a new
// attacker, as when history changes while the groups are recomputed. It
// never marks a group handled.
func TestEmailGroupsResultOlderThanHistoryIsNotHandled(t *testing.T) {
	withMemoAges(t, time.Hour, time.Hour)
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now().Add(-time.Minute)
	s.store.AppendHistory([]alert.Finding{emailFinding("mail_bruteforce", alert.High, "user@example.com", "", "203.0.113.7", now)})
	writeFirewallState(t, s.cfg.StatePath, firewall.FirewallState{Blocked: []firewall.BlockedEntry{{IP: "203.0.113.7"}}})
	stale := s.buildEmailGroupsResponse(now.Add(-time.Hour), time.Now(), "")
	s.store.AppendHistory([]alert.Finding{emailFinding("mail_bruteforce", alert.High, "user@example.com", "", "198.51.100.8", now.Add(time.Second))})
	s.emailMemos.memo("groups?").get(s.store.HistoryMark(), func() any { return stale })

	resp := getEmailGroups(t, s, "")
	if len(resp.Groups) != 1 || resp.Groups[0].Count != 1 || resp.Groups[0].BlockState != "all" {
		t.Fatalf("expected the older result: %+v", resp)
	}
	if resp.Groups[0].Handled || resp.HandledCount != 0 {
		t.Fatalf("result older than history marked handled: %+v", resp)
	}
}

// History changes on every append from any check. An unrelated finding
// inside the memo window must not bring handled groups back.
func TestEmailGroupsUnrelatedHistoryKeepsHandled(t *testing.T) {
	withMemoAges(t, time.Hour, time.Hour)
	s := newTestServerWithBbolt(t, "tok")
	now := time.Now().Add(-time.Minute)
	s.store.AppendHistory([]alert.Finding{emailFinding("mail_bruteforce", alert.High, "user@example.com", "", "203.0.113.7", now)})
	writeFirewallState(t, s.cfg.StatePath, firewall.FirewallState{Blocked: []firewall.BlockedEntry{{IP: "203.0.113.7"}}})
	if resp := getEmailGroups(t, s, ""); len(resp.Groups) != 1 || !resp.Groups[0].Handled || resp.HandledCount != 1 {
		t.Fatalf("complete history should be handled: %+v", resp)
	}
	s.store.AppendHistory([]alert.Finding{{Severity: alert.Warning, Check: "waf_status", Message: "WAF off", Timestamp: now.Add(time.Second)}})
	resp := getEmailGroups(t, s, "")
	if len(resp.Groups) != 1 || !resp.Groups[0].Handled || resp.HandledCount != 1 {
		t.Fatalf("unrelated finding unhandled a blocked group: %+v", resp)
	}
}

// Successful logins can mean stolen credentials; account sprays name only
// their latest source. Neither is resolved by blocking the listed address.
func TestEmailGroupsKeepLoginAndDistributedEvidence(t *testing.T) {
	now := time.Now()
	for _, check := range []string{"email_suspicious_geo", "mail_account_spray", "smtp_account_spray"} {
		t.Run(check, func(t *testing.T) {
			var findings []alert.Finding
			for i := 0; i < 3; i++ {
				findings = append(findings, emailFinding("mail_bruteforce", alert.High, "user@example.com", "", "203.0.113.7", now))
			}
			// Beyond the three displayed samples, but still part of the group.
			findings = append(findings, emailFinding(check, alert.High, "user@example.com", "", "203.0.113.7", now.Add(-time.Minute)))
			groups := buildEmailGroups(findings, now.Add(-time.Hour), now, "")
			annotateEmailGroups(groups, map[netip.Addr]bool{netip.MustParseAddr("203.0.113.7"): true}, nil)
			if len(groups) != 1 || groups[0].Count != 4 || groups[0].BlockState != "all" || groups[0].Handled {
				t.Fatalf("blocking one source hid evidence needing attention: %+v", groups)
			}
		})
	}
}
