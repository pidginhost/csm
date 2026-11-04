package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

const loginSprayTTL = 720 * time.Hour

func loginSprayFinding(ip string) alert.Finding {
	return alert.Finding{Severity: alert.Critical, Check: "smtp_bruteforce", SourceIP: ip, Message: "SMTP brute force from " + ip + ": failed logins on 2 mailboxes", Timestamp: time.Now(), BlockTTL: loginSprayTTL}
}

func perIPMailFinding(ip string) alert.Finding {
	return alert.Finding{Severity: alert.Critical, Check: "mail_bruteforce", SourceIP: ip, Message: "Mail auth brute force from " + ip, Timestamp: time.Now()}
}

func wafFinding(ip string) alert.Finding {
	return alert.Finding{Severity: alert.Critical, Check: "waf_attack_blocked", SourceIP: ip, Message: "WAF attack from " + ip, Timestamp: time.Now()}
}

func blockTimeouts(calls []blockCall) map[string]time.Duration {
	got := make(map[string]time.Duration, len(calls))
	for _, c := range calls {
		got[c.ip] = c.timeout
	}
	return got
}

// expiresNear reports whether at lies within a minute of now+ttl.
func expiresNear(at time.Time, ttl time.Duration) bool {
	want := time.Now().Add(ttl)
	return at.After(want.Add(-time.Minute)) && at.Before(want.Add(time.Minute))
}

// recordingAdmissionBlocker records the scan admission each durable request
// carries.
type recordingAdmissionBlocker struct {
	scanAdmissionBlocker
	admissions map[string]*firewall.ScanAdmission
}

func (b *recordingAdmissionBlocker) BlockIPRequest(req firewall.ActionRequest, budget *firewall.ScanAdmission) (firewall.BlockOutcome, error) {
	if b.admissions == nil {
		b.admissions = make(map[string]*firewall.ScanAdmission)
	}
	b.admissions[req.Target] = budget
	return b.scanAdmissionBlocker.BlockIPRequest(req, budget)
}

// A spray block lasts its own length in the firewall, the threat DB and the
// tracker; any other finding keeps block_expiry.
func TestAutoBlockUsesFindingTTL(t *testing.T) {
	cfg := pendingTestConfig(t)
	b := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
	applyBlockTestSetup(t, b)
	AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.71"), perIPMailFinding("192.0.2.72")})

	want := map[string]time.Duration{"192.0.2.71": loginSprayTTL, "192.0.2.72": time.Hour}
	if got := blockTimeouts(b.calls); len(got) != 2 || got["192.0.2.71"] != want["192.0.2.71"] || got["192.0.2.72"] != want["192.0.2.72"] {
		t.Fatalf("block timeouts = %v, want %v", got, want)
	}
	for ip, ttl := range want {
		if m, ok := GetThreatDB().LookupMatch(ip); !ok || !expiresNear(m.ExpiresAt, ttl) {
			t.Errorf("threat row for %s = %+v, want expiry in %s", ip, m, ttl)
		}
	}
	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 2 {
		t.Fatalf("tracker = %+v, want both blocks", state.IPs)
	}
	for _, e := range state.IPs {
		if !expiresNear(e.ExpiresAt, want[e.IP]) {
			t.Errorf("tracker expiry for %s = %v, want in %s", e.IP, e.ExpiresAt, want[e.IP])
		}
	}
}

// Findings from two trackers can name one address in one batch: the longer
// length and the spray flag win in either order.
func TestAutoBlockPendingKeepsLongestTTL(t *testing.T) {
	const ip = "192.0.2.73"
	for name, findings := range map[string][]alert.Finding{
		"old rule first": {perIPMailFinding(ip), loginSprayFinding(ip)},
		"spray first":    {loginSprayFinding(ip), perIPMailFinding(ip)},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			b := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, b)
			AutoBlockIPs(cfg, findings)
			if len(b.calls) != 1 || b.calls[0].timeout != loginSprayTTL {
				t.Fatalf("block calls = %+v, want one %s block", b.calls, loginSprayTTL)
			}
			if state := loadBlockState(cfg.StatePath); state.LoginSprayBlocksThisHour != 1 || state.BlocksThisHour != 0 {
				t.Fatalf("counters spray=%d scan=%d, want the block counted as a spray block", state.LoginSprayBlocksThisHour, state.BlocksThisHour)
			}
		})
	}
}

// A spray candidate over its hourly budget waits in the saved queue and
// keeps its length and flag for the next hour.
func TestAutoBlockSprayTTLSurvivesRequeue(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1
	now := time.Now()
	priorNow := autoBlockNow
	autoBlockNow = func() time.Time { return now }
	t.Cleanup(func() { autoBlockNow = priorNow })
	saveBlockState(cfg.StatePath, &blockState{HourKey: now.Format("2006-01-02T15"), LoginSprayBlocksThisHour: 1})
	b := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
	applyBlockTestSetup(t, b)

	AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.74")})
	state := loadBlockState(cfg.StatePath)
	if len(b.calls) != 0 || len(state.Pending) != 1 {
		t.Fatalf("calls = %+v, pending = %+v, want the candidate queued", b.calls, state.Pending)
	}
	if p := state.Pending[0]; p.TTL != loginSprayTTL || !p.LoginSpray {
		t.Fatalf("queued candidate = %+v, want ttl %s and the spray flag", p, loginSprayTTL)
	}

	autoBlockNow = func() time.Time { return now.Add(time.Hour) }
	AutoBlockIPs(cfg, nil)
	if len(b.calls) != 1 || b.calls[0].timeout != loginSprayTTL {
		t.Fatalf("retry calls = %+v, want one %s block", b.calls, loginSprayTTL)
	}
	if state := loadBlockState(cfg.StatePath); state.LoginSprayBlocksThisHour != 1 || state.BlocksThisHour != 0 {
		t.Fatalf("counters spray=%d scan=%d after the retry", state.LoginSprayBlocksThisHour, state.BlocksThisHour)
	}
}

// A rejected durable request drops its identity and admitted length; the
// fresh attempt still asks for the spray length, outside the scan budget.
func TestAutoBlockSprayTTLSurvivesRejectedRetry(t *testing.T) {
	cfg := pendingTestConfig(t)
	b := &recordingAdmissionBlocker{scanAdmissionBlocker: scanAdmissionBlocker{fail: firewall.ErrActionFailed}}
	applyBlockTestSetup(t, b)
	AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.75")})
	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 1 || state.Pending[0].ActionID != "" || state.Pending[0].TTL != loginSprayTTL || !state.Pending[0].LoginSpray {
		t.Fatalf("rejected candidate = %+v, want a fresh retry with the spray length", state.Pending)
	}
	b.fail = nil
	AutoBlockIPs(cfg, nil)
	if len(b.requests) != 2 || b.requests[0].TTL != loginSprayTTL || b.requests[1].TTL != loginSprayTTL || b.requests[0].ID == b.requests[1].ID {
		t.Fatalf("requests = %+v, want two %s attempts with new identity", b.requests, loginSprayTTL)
	}
	if adm := b.admissions["192.0.2.75"]; adm != nil {
		t.Fatalf("retry charged the scan budget: %+v", adm)
	}
}

// An address already blocked by any path keeps its block: a spray verdict
// neither re-blocks nor lengthens it.
func TestAutoBlockSprayTTLDoesNotExtendExistingBlock(t *testing.T) {
	const ip = "192.0.2.76"
	for _, tracked := range []bool{true, false} {
		name := "kernel only"
		if tracked {
			name = "tracked"
		}
		t.Run(name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			b := &preBlockedIPBlocker{recordingIPBlocker: &recordingIPBlocker{}, live: map[string]bool{ip: true}}
			applyBlockTestSetup(t, b)
			expires := time.Now().Add(time.Hour)
			GetThreatDB().AddTemporary(ip, "CSM auto-block: per-IP rule", time.Hour)
			if tracked {
				saveBlockState(cfg.StatePath, &blockState{IPs: []blockedIP{{IP: ip, Reason: "per-IP rule", BlockedAt: time.Now(), ExpiresAt: expires}}})
			}
			AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding(ip)})
			if len(b.calls) != 0 {
				t.Fatalf("block calls = %+v, want none", b.calls)
			}
			state := loadBlockState(cfg.StatePath)
			if len(state.Pending) != 0 || state.LoginSprayBlocksThisHour != 0 {
				t.Fatalf("state = %+v, want nothing queued or counted", state)
			}
			if tracked && (len(state.IPs) != 1 || !state.IPs[0].ExpiresAt.Equal(expires)) {
				t.Fatalf("tracker = %+v, want the original expiry %v", state.IPs, expires)
			}
			if m, ok := GetThreatDB().LookupMatch(ip); !ok || !expiresNear(m.ExpiresAt, time.Hour) {
				t.Fatalf("threat row = %+v, want the original hour", m)
			}
		})
	}
}

// Spray blocks and every other scan block draw on separate hourly budgets
// of the same size.
func TestAutoBlockSprayBudgetSeparate(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		scanUsed, sprayUsed  int
		blocked, queued      string
		wantScan, wantSpray  int
		wantTimeout          time.Duration
		wantQueuedLoginSpray bool
	}{
		{name: "spray budget full", sprayUsed: 2, blocked: "192.0.2.78", queued: "192.0.2.77", wantScan: 1, wantSpray: 2, wantTimeout: time.Hour, wantQueuedLoginSpray: true},
		{name: "scan budget full", scanUsed: 2, blocked: "192.0.2.77", queued: "192.0.2.78", wantScan: 2, wantSpray: 1, wantTimeout: loginSprayTTL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.MaxBlocksPerHour = 2
			now := time.Now()
			priorNow := autoBlockNow
			autoBlockNow = func() time.Time { return now }
			t.Cleanup(func() { autoBlockNow = priorNow })
			saveBlockState(cfg.StatePath, &blockState{HourKey: now.Format("2006-01-02T15"), BlocksThisHour: tc.scanUsed, LoginSprayBlocksThisHour: tc.sprayUsed})
			b := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
			applyBlockTestSetup(t, b)

			AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.77"), wafFinding("192.0.2.78")})
			if len(b.calls) != 1 || b.calls[0].ip != tc.blocked || b.calls[0].timeout != tc.wantTimeout {
				t.Fatalf("block calls = %+v, want only %s for %s", b.calls, tc.blocked, tc.wantTimeout)
			}
			state := loadBlockState(cfg.StatePath)
			if len(state.Pending) != 1 || state.Pending[0].IP != tc.queued || state.Pending[0].LoginSpray != tc.wantQueuedLoginSpray {
				t.Fatalf("pending = %+v, want %s queued", state.Pending, tc.queued)
			}
			if state.BlocksThisHour != tc.wantScan || state.LoginSprayBlocksThisHour != tc.wantSpray {
				t.Fatalf("counters scan=%d spray=%d, want %d and %d", state.BlocksThisHour, state.LoginSprayBlocksThisHour, tc.wantScan, tc.wantSpray)
			}
		})
	}
}

// The durable store admits one budget per hour, the scan budget; a spray
// block must not charge it.
func TestAutoBlockSprayBlocksSkipDurableScanBudget(t *testing.T) {
	cfg := pendingTestConfig(t)
	b := &recordingAdmissionBlocker{}
	applyBlockTestSetup(t, b)
	AutoBlockIPs(cfg, []alert.Finding{loginSprayFinding("192.0.2.79"), wafFinding("192.0.2.80")})
	if len(b.admissions) != 2 {
		t.Fatalf("durable requests = %+v, want two", b.requests)
	}
	if adm := b.admissions["192.0.2.79"]; adm != nil {
		t.Errorf("spray block charged the scan budget: %+v", adm)
	}
	if adm := b.admissions["192.0.2.80"]; adm == nil {
		t.Error("WAF block skipped the scan budget")
	}
	for _, r := range b.requests {
		if want := map[string]time.Duration{"192.0.2.79": loginSprayTTL, "192.0.2.80": time.Hour}[r.Target]; r.TTL != want {
			t.Errorf("durable TTL for %s = %s, want %s", r.Target, r.TTL, want)
		}
	}
}

// The per-IP mail rules carry no length of their own: block_expiry, the
// scan budget and no spray flag.
func TestAutoBlockOldRuleKeepsGlobalExpiry(t *testing.T) {
	cfg := pendingTestConfig(t)
	b := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
	applyBlockTestSetup(t, b)
	smtp := loginSprayFinding("192.0.2.81")
	smtp.BlockTTL = 0
	AutoBlockIPs(cfg, []alert.Finding{smtp, perIPMailFinding("192.0.2.82")})
	if got := blockTimeouts(b.calls); len(got) != 2 || got["192.0.2.81"] != time.Hour || got["192.0.2.82"] != time.Hour {
		t.Fatalf("block timeouts = %v, want block_expiry for both", got)
	}
	if state := loadBlockState(cfg.StatePath); state.BlocksThisHour != 2 || state.LoginSprayBlocksThisHour != 0 {
		t.Fatalf("counters scan=%d spray=%d, want both on the scan budget", state.BlocksThisHour, state.LoginSprayBlocksThisHour)
	}
}

// Nothing in the durable store caps a spray block, so a spray retry with an
// identity still draws on the spray budget; a scan retry still passes the
// full scan budget, which the store caps at admission.
func TestAutoBlockSprayDurableRetriesUseSprayBudget(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 2
	now := time.Now()
	priorNow := autoBlockNow
	autoBlockNow = func() time.Time { return now }
	t.Cleanup(func() { autoBlockNow = priorNow })
	retry := func(ip, check, id string, ttl time.Duration) pendingIP {
		return pendingIP{ActionID: id, ActionTTL: max(ttl, time.Hour), IP: ip, Reason: check + " from " + ip, Check: check, Severity: alert.Critical, TTL: ttl, LoginSpray: ttl > 0, QueuedAt: now}
	}
	saveBlockState(cfg.StatePath, &blockState{HourKey: now.Format("2006-01-02T15"), Pending: []pendingIP{
		retry("192.0.2.83", "smtp_bruteforce", "spray-1", loginSprayTTL),
		retry("192.0.2.84", "smtp_bruteforce", "spray-2", loginSprayTTL),
		retry("192.0.2.85", "smtp_bruteforce", "spray-3", loginSprayTTL),
		retry("192.0.2.86", "waf_attack_blocked", "scan-1", 0),
	}})
	// The scan budget is spent; the store charged the scan retry already.
	b := &recordingAdmissionBlocker{scanAdmissionBlocker: scanAdmissionBlocker{used: 2}}
	applyBlockTestSetup(t, b)

	AutoBlockIPs(cfg, nil)
	spray := 0
	scanRetried := false
	for _, r := range b.requests {
		switch {
		case r.ID == "scan-1":
			scanRetried = true
		case r.TTL == loginSprayTTL:
			spray++
		}
	}
	if spray != 2 || !scanRetried {
		t.Fatalf("requests = %+v, want 2 spray retries and the scan retry", b.requests)
	}
	state := loadBlockState(cfg.StatePath)
	if state.LoginSprayBlocksThisHour != 2 {
		t.Fatalf("spray counter = %d, want 2", state.LoginSprayBlocksThisHour)
	}
	if len(state.Pending) != 1 {
		t.Fatalf("pending = %+v, want the third spray retry", state.Pending)
	}
	if p := state.Pending[0]; p.ActionID == "" || p.TTL != loginSprayTTL || !p.LoginSpray {
		t.Fatalf("queued retry = %+v, want its identity, ttl and flag", p)
	}
}
