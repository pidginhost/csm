package checks

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

type scanAdmissionBlocker struct {
	outcomeStubBlocker
	used     int
	readErr  error
	requests []firewall.ActionRequest
	fail     error
}

func (b *scanAdmissionBlocker) DurableActionsEnabled() bool            { return true }
func (b *scanAdmissionBlocker) FirewallScanBudget(string) (int, error) { return b.used, b.readErr }
func (b *scanAdmissionBlocker) BlockIPRequest(req firewall.ActionRequest, budget *firewall.ScanAdmission) (firewall.BlockOutcome, error) {
	b.requests = append(b.requests, req)
	if b.fail != nil {
		return firewall.BlockOutcomeNoop, b.fail
	}
	b.used++
	return firewall.BlockOutcomeLive, nil
}

func TestAutoBlockDurableBudgetSurvivesTrackerReset(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1
	b := &scanAdmissionBlocker{used: 1}
	applyBlockTestSetup(t, b)
	finding := alert.Finding{Severity: alert.Critical, Check: "wp_login_bruteforce", SourceIP: "192.0.2.61", Message: "confirmed attack", Timestamp: time.Now()}
	AutoBlockIPs(cfg, []alert.Finding{finding})
	if len(b.requests) != 0 || len(b.calls) != 0 {
		t.Fatal("lost tracker reset durable hourly budget")
	}
	if state := loadBlockState(cfg.StatePath); len(state.Pending) != 1 {
		t.Fatalf("rate-limited finding not retained: %#v", state)
	}
}
func TestAutoBlockDurableBudgetReadFailureRetainsCandidate(t *testing.T) {
	cfg := pendingTestConfig(t)
	b := &scanAdmissionBlocker{readErr: errors.New("budget storage unavailable")}
	applyBlockTestSetup(t, b)
	AutoBlockIPs(cfg, []alert.Finding{{Severity: alert.Critical, Check: "wp_login_bruteforce", SourceIP: "192.0.2.62", Message: "confirmed attack", Timestamp: time.Now()}})
	if len(b.requests) != 0 || len(b.calls) != 0 {
		t.Fatal("unreadable budget allowed mutation")
	}
	if state := loadBlockState(cfg.StatePath); len(state.Pending) != 1 {
		t.Fatalf("candidate lost on budget read failure: %#v", state)
	}
}
func TestAutoBlockDurableRetryPreservesRequestID(t *testing.T) {
	cfg := pendingTestConfig(t)
	b := &scanAdmissionBlocker{fail: firewall.ErrActionUnknown}
	applyBlockTestSetup(t, b)
	AutoBlockIPs(cfg, []alert.Finding{{Severity: alert.Critical, Check: "wp_login_bruteforce", SourceIP: "192.0.2.63", Message: "confirmed attack", Timestamp: time.Now()}})
	AutoBlockIPs(cfg, nil)
	if len(b.requests) != 2 || b.requests[0].ID == "" || b.requests[0].ID != b.requests[1].ID {
		t.Fatalf("retry identities = %#v", b.requests)
	}
}

func TestAutoBlockDurableRetryPreservesAdmittedTTL(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.BlockExpiry = "30m"
	b := &scanAdmissionBlocker{fail: firewall.ErrActionUnknown}
	applyBlockTestSetup(t, b)
	finding := alert.Finding{Severity: alert.Critical, Check: "wp_login_bruteforce", SourceIP: "192.0.2.64", Message: "confirmed attack", Timestamp: time.Now()}
	AutoBlockIPs(cfg, []alert.Finding{finding})
	cfg.AutoResponse.BlockExpiry = "2h"
	finding.Message = "new evidence from the same source"
	AutoBlockIPs(cfg, []alert.Finding{finding})
	if len(b.requests) != 2 || b.requests[0] != b.requests[1] {
		t.Fatalf("retry changed the admitted request: %#v", b.requests)
	}
	if b.requests[1].TTL != 30*time.Minute {
		t.Fatalf("retry TTL = %s, want original 30m", b.requests[1].TTL)
	}
}

func TestAutoBlockDurableRejectedActionGetsNewRetryIdentity(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.BlockExpiry = "30m"
	b := &scanAdmissionBlocker{fail: firewall.ErrActionFailed}
	applyBlockTestSetup(t, b)
	finding := alert.Finding{Severity: alert.Critical, Check: "wp_login_bruteforce", SourceIP: "192.0.2.65", Message: "confirmed attack", Timestamp: time.Now()}
	AutoBlockIPs(cfg, []alert.Finding{finding})
	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 1 || state.Pending[0].ActionID != "" {
		t.Fatalf("proven rejected action is not eligible for a fresh retry: %#v", state.Pending)
	}
	cfg.AutoResponse.BlockExpiry = "2h"
	b.fail = nil
	AutoBlockIPs(cfg, nil)
	if len(b.requests) != 2 || b.requests[0].ID == "" || b.requests[1].ID == "" || b.requests[0].ID == b.requests[1].ID {
		t.Fatalf("new attempt reused rejected identity: %#v", b.requests)
	}
	if b.requests[1].TTL != 2*time.Hour || b.requests[1].FindingID != b.requests[0].FindingID || b.requests[1].Source != b.requests[0].Source {
		t.Fatalf("new attempt did not retain cause and use current policy: %#v", b.requests)
	}
	if state := loadBlockState(cfg.StatePath); len(state.Pending) != 0 || len(state.IPs) != 1 {
		t.Fatalf("fresh retry did not finish the candidate: %#v", state)
	}
}

type subnetAdmissionBlocker struct {
	scanAdmissionBlocker
	budgets   []*firewall.ScanAdmission
	legacy    int
	subnetErr error
}

func (b *subnetAdmissionBlocker) BlockSubnet(string, string, time.Duration) error {
	b.legacy++
	return b.subnetErr
}
func (b *subnetAdmissionBlocker) BlockSubnetRequest(req firewall.ActionRequest, budget *firewall.ScanAdmission) error {
	b.budgets = append(b.budgets, budget)
	return b.subnetErr
}
func TestAutoBlockASNSubnetSharesDurableScanBudget(t *testing.T) {
	cfg := pendingTestConfig(t)
	b := &subnetAdmissionBlocker{}
	applyBlockTestSetup(t, b)
	AutoBlockIPs(cfg, []alert.Finding{{Severity: alert.Critical, Check: "http_asn_crawl", Message: "confirmed crawl", CIDRs: []string{"192.0.2.0/24"}, Timestamp: time.Now()}})
	if b.legacy != 0 || len(b.budgets) != 1 || b.budgets[0] == nil {
		t.Fatalf("subnet bypassed admission: legacy=%d budgets=%#v", b.legacy, b.budgets)
	}
}

type auditPendingScanBlocker struct{ scanAdmissionBlocker }

func (b *auditPendingScanBlocker) BlockIPRequest(req firewall.ActionRequest, budget *firewall.ScanAdmission) (firewall.BlockOutcome, error) {
	b.requests = append(b.requests, req)
	b.used++
	return firewall.BlockOutcomeLive, firewall.ErrActionAuditPending
}
func TestAutoBlockDurableAuditPendingRetainsFindingsAndBudget(t *testing.T) {
	cfg := pendingTestConfig(t)
	b := &auditPendingScanBlocker{}
	applyBlockTestSetup(t, b)
	actions := AutoBlockIPs(cfg, []alert.Finding{{Severity: alert.Critical, Check: "wp_login_bruteforce", SourceIP: "192.0.2.66", Message: "confirmed attack", Timestamp: time.Now()}})
	if len(actions) != 1 {
		t.Fatalf("verified action findings lost: %#v", actions)
	}
	state := loadBlockState(cfg.StatePath)
	if state.BlocksThisHour != 1 || len(state.Pending) != 0 || len(state.IPs) != 1 {
		t.Fatalf("verified scan result lost: %#v", state)
	}
}

func (b *subnetAdmissionBlocker) IsBlocked(string) bool { return true }

func TestAutoSubnetAuditPendingRetainsAppliedFindings(t *testing.T) {
	for _, route := range []string{"smtp_subnet_spray", "mail_subnet_spray", "http_asn_crawl", "netblock"} {
		for _, tc := range []struct {
			name string
			err  error
			want int
		}{
			{name: "verified", err: firewall.ErrActionAuditPending, want: 1},
			{name: "unknown", err: firewall.ErrActionUnknown},
		} {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				cfg := pendingTestConfig(t)
				cfg.AutoResponse.MaxBlocksPerHour = 1
				b := &subnetAdmissionBlocker{subnetErr: tc.err}
				applyBlockTestSetup(t, b)
				finding := alert.Finding{Check: route, Severity: alert.Critical, Message: "confirmed attack from 192.0.2.0/24", Timestamp: time.Now()}
				findings := []alert.Finding{finding}
				if route == "http_asn_crawl" {
					findings[0].CIDRs = []string{"192.0.2.0/24", "198.51.100.0/24"}
				}
				if route == "netblock" {
					cfg.AutoResponse.NetBlock = true
					cfg.AutoResponse.NetBlockThreshold = 3
					findings = nil
					saveBlockState(cfg.StatePath, &blockState{IPs: []blockedIP{{IP: "192.0.2.91"}, {IP: "192.0.2.92"}, {IP: "192.0.2.93"}}})
				}
				actions := AutoBlockIPs(cfg, findings)
				if len(actions) != tc.want {
					t.Fatalf("applied subnet findings=%+v, want %d", actions, tc.want)
				}
				if route == "http_asn_crawl" {
					if state := loadBlockState(cfg.StatePath); state.BlocksThisHour != tc.want {
						t.Fatalf("accepted ASN budget=%d, want %d", state.BlocksThisHour, tc.want)
					}
					if tc.want > 0 && len(b.budgets) != 1 {
						t.Fatalf("audit error bypassed shared scan cap: attempts=%d", len(b.budgets))
					}
				}
			})
		}
	}
}

type promotionAuditBlocker struct {
	scanAdmissionBlocker
	promotionErr error
}

func (b *promotionAuditBlocker) PromoteToPermanentBlockWithFindingID(string, string, string) error {
	return b.promotionErr
}

func TestAutoPromotionAuditPendingRetainsAppliedFinding(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "verified", err: firewall.ErrActionAuditPending, want: true},
		{name: "unknown", err: firewall.ErrActionUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pendingTestConfig(t)
			cfg.AutoResponse.PermBlock = true
			cfg.AutoResponse.PermBlockCount = 2
			b := &promotionAuditBlocker{promotionErr: tc.err}
			applyBlockTestSetup(t, b)
			req := ApplyBlockRequest{IP: "192.0.2.94", FindingID: "promotion-cause", Source: BlockSourceIncident, TTL: time.Hour}
			if _, err := ApplyBlock(cfg, req); err != nil {
				t.Fatal(err)
			}
			result, err := ApplyBlock(cfg, req)
			if err != nil {
				t.Fatal(err)
			}
			promoted := false
			for _, finding := range result.Findings {
				promoted = promoted || strings.Contains(finding.Message, "AUTO-PERMBLOCK")
			}
			if promoted != tc.want {
				t.Fatalf("promotion finding=%t, want %t: %+v", promoted, tc.want, result.Findings)
			}
			if tracker := loadPermBlockTracker(cfg.StatePath); len(tracker.IPs[req.IP]) != 2 {
				t.Fatalf("applied blocks lost escalation history: %+v", tracker)
			}
		})
	}
}

type admittedScanBlocker struct {
	outcomeStubBlocker
	db *store.DB
}

func (b *admittedScanBlocker) DurableActionsEnabled() bool { return true }
func (b *admittedScanBlocker) FirewallScanBudget(window string) (int, error) {
	return b.db.ReadFirewallScanBudget(window)
}
func (b *admittedScanBlocker) BlockIPRequest(req firewall.ActionRequest, budget *firewall.ScanAdmission) (firewall.BlockOutcome, error) {
	before, revision, err := b.db.ReadFirewallState()
	if err != nil {
		return firewall.BlockOutcomeNoop, err
	}
	after := before
	after.Blocked = append(after.Blocked, firewall.BlockedEntry{IP: req.Target, Reason: req.Reason, BlockedAt: time.Now(), ExpiresAt: time.Now().Add(req.TTL)})
	action, fresh, err := b.db.AdmitFirewallAction(firewall.FirewallAction{Request: req, Before: before, After: after, Revision: revision, CreatedAt: time.Now(), Budget: budget})
	if err != nil {
		return firewall.BlockOutcomeNoop, err
	}
	if fresh {
		if _, err = b.db.TransitionFirewallAction(action.Request.ID, "executing", "", time.Now()); err != nil {
			return firewall.BlockOutcomeNoop, err
		}
		if _, err = b.db.TransitionFirewallAction(action.Request.ID, "unknown", "reply unavailable", time.Now()); err != nil {
			return firewall.BlockOutcomeNoop, err
		}
		return firewall.BlockOutcomeNoop, firewall.ErrActionUnknown
	}
	// The host boundary now proves the original mutation. A repeated request
	// records that outcome without creating a new effect or renewing expiry.
	_, err = b.db.TransitionFirewallAction(action.Request.ID, "verified", "", time.Now())
	return firewall.BlockOutcomeNoop, err
}

func TestAutoBlockDurablePendingAtCapReconcilesOriginalID(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = 1
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err = db.ReplaceFirewallState(0, firewall.FirewallState{}); err != nil {
		t.Fatal(err)
	}
	b := &admittedScanBlocker{db: db}
	applyBlockTestSetup(t, b)
	AutoBlockIPs(cfg, []alert.Finding{{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: "192.0.2.95", Message: "confirmed attack", Timestamp: time.Now()}})
	queued := loadBlockState(cfg.StatePath)
	if len(queued.Pending) != 1 || queued.Pending[0].ActionID == "" {
		t.Fatalf("missing admitted retry: %+v", queued)
	}
	actionID := queued.Pending[0].ActionID
	AutoBlockIPs(cfg, nil)
	action, err := db.ReadFirewallAction(actionID)
	if err != nil || action.Phase != "verified" {
		t.Fatalf("last-slot admission did not recover: phase=%s err=%v", action.Phase, err)
	}
	if used, budgetErr := db.ReadFirewallScanBudget(queued.HourKey); budgetErr != nil || used != 1 {
		t.Fatalf("recovery changed accepted budget: used=%d err=%v", used, budgetErr)
	}
	if state := loadBlockState(cfg.StatePath); len(state.Pending) != 0 {
		t.Fatalf("recovered identity remained pending: %+v", state.Pending)
	}
	// A retry identity whose admission never happened must still be refused
	// by the authoritative budget, even though it passes the outer retry gate.
	queued = loadBlockState(cfg.StatePath)
	queued.Pending = []pendingIP{{ActionID: "never-admitted", ActionTTL: time.Hour, IP: "192.0.2.96", Check: "wp_login_bruteforce", Severity: alert.Critical, Reason: "confirmed attack"}}
	saveBlockState(cfg.StatePath, queued)
	AutoBlockIPs(cfg, nil)
	if _, err = db.ReadFirewallAction("never-admitted"); !errors.Is(err, firewall.ErrActionMissing) {
		t.Fatalf("unadmitted retry bypassed authoritative cap: %v", err)
	}
	state, _, err := db.ReadFirewallState()
	if err != nil || len(state.Blocked) != 1 || state.Blocked[0].IP != "192.0.2.95" {
		t.Fatalf("unadmitted retry changed committed state: %+v %v", state, err)
	}
}
