package checks

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

// outcomeStubBlocker returns a fixed outcome/error and records calls. It
// implements the optional interfaces the chokepoint consults so tests can
// exercise the Cloudflare warning and permblock promotion paths.
type outcomeStubBlocker struct {
	outcome  firewall.BlockOutcome
	err      error
	calls    []blockCall
	cfCovers bool
	promoted []string
}

func (b *outcomeStubBlocker) BlockIP(ip, reason string, timeout time.Duration) error {
	_, err := b.BlockIPOutcome(ip, reason, timeout)
	return err
}

func (b *outcomeStubBlocker) BlockIPOutcome(ip, reason string, timeout time.Duration) (firewall.BlockOutcome, error) {
	b.calls = append(b.calls, blockCall{ip: ip, reason: reason, timeout: timeout})
	return b.outcome, b.err
}

func (b *outcomeStubBlocker) UnblockIP(string) error { return nil }
func (b *outcomeStubBlocker) IsBlocked(string) bool  { return false }

func (b *outcomeStubBlocker) CloudflareCovers(string) bool { return b.cfCovers }

func (b *outcomeStubBlocker) PromoteToPermanentBlock(ip, reason string) error {
	b.promoted = append(b.promoted, ip)
	return nil
}

func applyBlockTestSetup(t *testing.T, b IPBlocker) {
	t.Helper()
	t.Cleanup(SetGlobalThreatDBForTest(t.TempDir()))
	oldBlocker := getIPBlocker()
	SetIPBlocker(b)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })
}

// A live outcome must leave the same evidence trail a scan auto-block
// leaves: threat-DB row, blocked-IPs tracker entry, and a Critical
// auto_block finding carrying the human reason.
func TestApplyBlockLiveRecordsEvidence(t *testing.T) {
	cfg := pendingTestConfig(t)
	blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
	applyBlockTestSetup(t, blocker)

	res, err := ApplyBlock(cfg, ApplyBlockRequest{
		IP:           "203.0.113.50",
		EngineReason: "CSM challenge-timeout: wp brute",
		Reason:       "challenge timeout after wp brute",
		TTL:          time.Hour,
		Source:       BlockSourceChallenge,
	})
	if err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}
	if res.Outcome != firewall.BlockOutcomeLive {
		t.Fatalf("outcome = %q, want live", res.Outcome)
	}
	if len(blocker.calls) != 1 || blocker.calls[0].reason != "CSM challenge-timeout: wp brute" {
		t.Fatalf("engine calls = %+v, want one call with the engine reason", blocker.calls)
	}

	if _, found := GetThreatDB().Lookup("203.0.113.50"); !found {
		t.Error("live block left no threat-DB row")
	}
	state := loadBlockState(cfg.StatePath)
	if len(state.IPs) != 1 || state.IPs[0].IP != "203.0.113.50" {
		t.Fatalf("tracker IPs = %+v, want the blocked IP", state.IPs)
	}
	if state.IPs[0].ExpiresAt.Before(time.Now().Add(50 * time.Minute)) {
		t.Errorf("tracker expiry = %v, want ~1h out", state.IPs[0].ExpiresAt)
	}

	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", res.Findings)
	}
	f := res.Findings[0]
	if f.Check != "auto_block" || f.Severity != alert.Critical {
		t.Errorf("finding check/severity = %s/%s, want auto_block/Critical", f.Check, f.Severity)
	}
	if !strings.Contains(f.Message, "AUTO-BLOCK: 203.0.113.50 blocked") {
		t.Errorf("finding message = %q, want the standard AUTO-BLOCK form", f.Message)
	}
	if !strings.Contains(f.Details, "Reason: challenge timeout after wp brute") {
		t.Errorf("finding details = %q, want the human reason", f.Details)
	}
	if f.SourceIP != "203.0.113.50" {
		t.Errorf("finding SourceIP = %q, want structured IP", f.SourceIP)
	}
}

// Dry-run must stay observable but evidence-free: a Warning notice and no
// threat-DB row or tracker entry, mirroring the scan path's contract.
func TestApplyBlockDryRunEmitsNoticeWithoutEvidence(t *testing.T) {
	cfg := pendingTestConfig(t)
	blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeDryRun}
	applyBlockTestSetup(t, blocker)

	res, err := ApplyBlock(cfg, ApplyBlockRequest{
		IP: "203.0.113.51", EngineReason: "CSM auto-block: x", Reason: "x",
		TTL: time.Hour, Source: BlockSourceScan,
	})
	if err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != alert.Warning ||
		!strings.Contains(res.Findings[0].Message, "[dry-run]") {
		t.Fatalf("findings = %+v, want one dry-run Warning notice", res.Findings)
	}
	if _, found := GetThreatDB().Lookup("203.0.113.51"); found {
		t.Error("dry-run wrote a threat-DB row")
	}
	if state := loadBlockState(cfg.StatePath); len(state.IPs) != 0 {
		t.Errorf("dry-run wrote tracker entries: %+v", state.IPs)
	}
}

// Allowed, allowlisted, and noop outcomes record nothing and stay silent.
func TestApplyBlockNonLiveOutcomesStaySilent(t *testing.T) {
	for _, outcome := range []firewall.BlockOutcome{
		firewall.BlockOutcomeAllowed,
		firewall.BlockOutcomeAllowlisted,
		firewall.BlockOutcomeNoop,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			cfg := pendingTestConfig(t)
			blocker := &outcomeStubBlocker{outcome: outcome}
			applyBlockTestSetup(t, blocker)

			res, err := ApplyBlock(cfg, ApplyBlockRequest{
				IP: "203.0.113.52", EngineReason: "r", Reason: "r",
				TTL: time.Hour, Source: BlockSourceCentral,
			})
			if err != nil {
				t.Fatalf("ApplyBlock: %v", err)
			}
			if len(res.Findings) != 0 {
				t.Fatalf("findings = %+v, want none", res.Findings)
			}
			if _, found := GetThreatDB().Lookup("203.0.113.52"); found {
				t.Error("non-live outcome wrote a threat-DB row")
			}
		})
	}
}

// Engine errors surface to the caller and leave no partial evidence.
func TestApplyBlockErrorLeavesNoEvidence(t *testing.T) {
	cfg := pendingTestConfig(t)
	blocker := &outcomeStubBlocker{
		outcome: firewall.BlockOutcomeNoop,
		err:     errors.New("netlink receive: no buffer space available"),
	}
	applyBlockTestSetup(t, blocker)

	_, err := ApplyBlock(cfg, ApplyBlockRequest{
		IP: "203.0.113.53", EngineReason: "r", Reason: "r",
		TTL: time.Hour, Source: BlockSourceIncident,
	})
	if err == nil {
		t.Fatal("engine error not surfaced")
	}
	if _, found := GetThreatDB().Lookup("203.0.113.53"); found {
		t.Error("failed block wrote a threat-DB row")
	}
	if state := loadBlockState(cfg.StatePath); len(state.IPs) != 0 {
		t.Errorf("failed block wrote tracker entries: %+v", state.IPs)
	}
}

// A nil wired blocker is an error, not a silent no-op: callers requeue or
// log, they must not believe the block landed.
func TestApplyBlockWithoutEngineErrors(t *testing.T) {
	cfg := pendingTestConfig(t)
	t.Cleanup(SetGlobalThreatDBForTest(t.TempDir()))
	oldBlocker := getIPBlocker()
	SetIPBlocker(nil)
	t.Cleanup(func() { SetIPBlocker(oldBlocker) })

	before := blockOutcomeMetricValue(t, "error", BlockSourceChallenge)
	res, err := ApplyBlock(cfg, ApplyBlockRequest{
		IP: "203.0.113.54", EngineReason: "r", Reason: "r",
		TTL: time.Hour, Source: BlockSourceChallenge,
	})
	if err == nil {
		t.Fatal("nil engine did not error")
	}
	if res.Outcome != firewall.BlockOutcomeNoop {
		t.Fatalf("outcome = %q, want noop", res.Outcome)
	}
	if got := blockOutcomeMetricValue(t, "error", BlockSourceChallenge); got != before+1 {
		t.Fatalf("error/challenge = %v, want %v", got, before+1)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", res.Findings)
	}
}

// Chokepoint blocks count toward permanent-block escalation regardless of
// source: N temp blocks within the interval promote the IP, closing the
// gap where challenge/central blocks never advanced the counter.
func TestApplyBlockCountsPermBlockEscalation(t *testing.T) {
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.PermBlock = true
	cfg.AutoResponse.PermBlockCount = 2
	blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive}
	applyBlockTestSetup(t, blocker)

	req := ApplyBlockRequest{
		IP: "203.0.113.55", EngineReason: "r", Reason: "r",
		TTL: time.Hour, Source: BlockSourceChallenge,
	}
	res1, err := ApplyBlock(cfg, req)
	if err != nil || len(blocker.promoted) != 0 {
		t.Fatalf("first block: err=%v promoted=%v, want no promotion yet", err, blocker.promoted)
	}
	_ = res1
	res2, err := ApplyBlock(cfg, req)
	if err != nil {
		t.Fatalf("second block: %v", err)
	}
	if len(blocker.promoted) != 1 || blocker.promoted[0] != "203.0.113.55" {
		t.Fatalf("promoted = %v, want the escalated IP", blocker.promoted)
	}
	var sawPromotion bool
	for _, f := range res2.Findings {
		if strings.Contains(f.Message, "AUTO-PERMBLOCK: 203.0.113.55") {
			sawPromotion = true
		}
	}
	if !sawPromotion {
		t.Fatalf("findings = %+v, want an AUTO-PERMBLOCK promotion finding", res2.Findings)
	}
}

// Blocking an IP inside a Cloudflare allow range must carry the standard
// coverage warning in the finding details, same as the scan path.
func TestApplyBlockCarriesCloudflareWarning(t *testing.T) {
	cfg := pendingTestConfig(t)
	blocker := &outcomeStubBlocker{outcome: firewall.BlockOutcomeLive, cfCovers: true}
	applyBlockTestSetup(t, blocker)

	res, err := ApplyBlock(cfg, ApplyBlockRequest{
		IP: "203.0.113.56", EngineReason: "r", Reason: "r",
		TTL: time.Hour, Source: BlockSourceCentral,
	})
	if err != nil {
		t.Fatalf("ApplyBlock: %v", err)
	}
	if len(res.Findings) != 1 || !strings.Contains(res.Findings[0].Details, firewall.CloudflareCoverageWarning) {
		t.Fatalf("findings = %+v, want the Cloudflare coverage warning", res.Findings)
	}
}

type onceLiveBlocker struct {
	mu      sync.Mutex
	blocked bool
}

func (b *onceLiveBlocker) BlockIP(ip, reason string, timeout time.Duration) error {
	_, err := b.BlockIPOutcome(ip, reason, timeout)
	return err
}

func (b *onceLiveBlocker) BlockIPOutcome(string, string, time.Duration) (firewall.BlockOutcome, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.blocked {
		return firewall.BlockOutcomeNoop, nil
	}
	b.blocked = true
	return firewall.BlockOutcomeLive, nil
}

func (b *onceLiveBlocker) UnblockIP(string) error { return nil }
func (b *onceLiveBlocker) IsBlocked(string) bool  { return true }

func TestApplyBlockConcurrentSourcesRecordOneAppliedBlock(t *testing.T) {
	cfg := pendingTestConfig(t)
	blocker := &onceLiveBlocker{}
	applyBlockTestSetup(t, blocker)

	start := make(chan struct{})
	results := make(chan ApplyBlockResult, 2)
	errs := make(chan error, 2)
	for _, source := range []string{BlockSourceChallenge, BlockSourceIncident} {
		go func(source string) {
			<-start
			res, err := ApplyBlock(cfg, ApplyBlockRequest{
				IP: "203.0.113.60", EngineReason: source, Reason: source,
				TTL: time.Hour, Source: source,
			})
			results <- res
			errs <- err
		}(source)
	}
	close(start)

	live, noop, findings := 0, 0, 0
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("ApplyBlock: %v", err)
		}
		res := <-results
		findings += len(res.Findings)
		switch res.Outcome {
		case firewall.BlockOutcomeLive:
			live++
		case firewall.BlockOutcomeNoop:
			noop++
		default:
			t.Fatalf("outcome = %q, want live or noop", res.Outcome)
		}
	}
	if live != 1 || noop != 1 || findings != 1 {
		t.Fatalf("live=%d noop=%d findings=%d, want 1/1/1", live, noop, findings)
	}
	if state := loadBlockState(cfg.StatePath); len(state.IPs) != 1 {
		t.Fatalf("tracker entries = %+v, want one", state.IPs)
	}
}
