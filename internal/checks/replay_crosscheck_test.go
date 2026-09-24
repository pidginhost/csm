package checks

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/responsereplay"
)

// The replay model is checked against the real admission path here: the same
// findings and starting state go through ChallengeThenBlock and through the
// model, and their counters, queues and block sets are compared. The live
// path drains candidates in Go map order, so only sets the live path fixes
// are compared exactly; for the rest the counts and the partition are.

func TestExportedClassifiersMatchInternalPolicy(t *testing.T) {
	names := append(AllCheckNames(), "ftp_login_realtime", "ssh_login_realtime", "unregistered_check",
		"outgoing_mail_hold_new", "spam_new", "modsec_new", "email_auth_failure_new", "email_compromised_new", "email_credential_new")
	checked := 0
	for _, name := range names {
		for _, sev := range []alert.Severity{alert.Warning, alert.High, alert.Critical} {
			for _, cpanel := range []bool{false, true} {
				for _, challenge := range []bool{false, true} {
					for _, scanner := range []string{"", responseChallenge, responseBlock} {
						cfg := &config.Config{}
						cfg.Challenge.Enabled = challenge
						cfg.AutoResponse.BlockCpanelLogins = cpanel
						cfg.AutoResponse.HTTPScannerAction = scanner
						f := alert.Finding{Check: name, Severity: sev}
						if BlockableFinding(f, cpanel) != blockableFinding(f, cpanel) {
							t.Errorf("BlockableFinding(%s, %v, cpanel=%v) disagrees", name, sev, cpanel)
						}
						if ChallengeRoutesFinding(cfg, f) != (responseActionForFinding(cfg, f) == responseChallenge) {
							t.Errorf("ChallengeRoutesFinding(%s, %v) disagrees", name, sev)
						}
						checked++
					}
				}
			}
		}
	}
	if checked < 1000 {
		t.Fatalf("only %d combinations checked", checked)
	}
	on := &config.Config{}
	on.Challenge.Enabled = true
	off := &config.Config{}
	scannerBlock := &config.Config{}
	scannerBlock.Challenge.Enabled = true
	scannerBlock.AutoResponse.HTTPScannerAction = responseBlock
	for _, tc := range []struct {
		cfg       *config.Config
		f         alert.Finding
		cpanel    bool
		blockable bool
		challenge bool
	}{
		{on, alert.Finding{Check: "smtp_bruteforce", Severity: alert.Critical}, false, true, false},
		{on, alert.Finding{Check: "wp_login_bruteforce", Severity: alert.High}, false, true, true},
		{off, alert.Finding{Check: "wp_login_bruteforce", Severity: alert.High}, false, true, false},
		{on, alert.Finding{Check: "mail_account_compromised", Severity: alert.High}, false, false, false},
		{on, alert.Finding{Check: "mail_account_compromised", Severity: alert.Critical}, false, true, false},
		{on, alert.Finding{Check: "ip_reputation", Severity: alert.High}, false, true, true},
		{on, alert.Finding{Check: "ip_reputation", Severity: alert.Critical}, false, true, false},
		{on, alert.Finding{Check: "http_scanner_profile", Severity: alert.High}, false, true, true},
		{scannerBlock, alert.Finding{Check: "http_scanner_profile", Severity: alert.High}, false, true, false},
		{on, alert.Finding{Check: "cpanel_multi_ip_login", Severity: alert.High}, false, false, false},
		{on, alert.Finding{Check: "cpanel_multi_ip_login", Severity: alert.High}, true, true, false},
		{on, alert.Finding{Check: "unregistered_check", Severity: alert.Critical}, false, false, false},
	} {
		if got := BlockableFinding(tc.f, tc.cpanel); got != tc.blockable {
			t.Errorf("BlockableFinding(%s %v cpanel=%v) = %v", tc.f.Check, tc.f.Severity, tc.cpanel, got)
		}
		if got := ChallengeRoutesFinding(tc.cfg, tc.f); got != tc.challenge {
			t.Errorf("ChallengeRoutesFinding(%s %v) = %v", tc.f.Check, tc.f.Severity, got)
		}
	}
}

// replayFakeBlocker is a firewall with virtual time. A block's lease ends
// when the test clock reaches it, as the kernel timeout does; an existing
// block is neither renewed nor counted again.
type replayFakeBlocker struct {
	clock    func() time.Time
	expiry   map[string]time.Time
	attempts int
	live     []string
}

func newReplayFakeBlocker(clock func() time.Time) *replayFakeBlocker {
	return &replayFakeBlocker{clock: clock, expiry: map[string]time.Time{}}
}

func (b *replayFakeBlocker) BlockIP(ip, reason string, timeout time.Duration) error {
	_, err := b.BlockIPOutcome(ip, reason, timeout)
	return err
}

func (b *replayFakeBlocker) BlockIPOutcome(ip, _ string, timeout time.Duration) (firewall.BlockOutcome, error) {
	b.attempts++
	if b.IsBlocked(ip) {
		return firewall.BlockOutcomeNoop, nil
	}
	var expiry time.Time
	if timeout > 0 {
		expiry = b.clock().Add(timeout)
	}
	b.expiry[ip] = expiry
	b.live = append(b.live, ip)
	return firewall.BlockOutcomeLive, nil
}

func (b *replayFakeBlocker) UnblockIP(ip string) error {
	delete(b.expiry, ip)
	return nil
}

func (b *replayFakeBlocker) IsBlocked(ip string) bool {
	expiry, ok := b.expiry[ip]
	return ok && (expiry.IsZero() || b.clock().Before(expiry))
}

func (b *replayFakeBlocker) liveCount() int {
	n := 0
	for ip := range b.expiry {
		if b.IsBlocked(ip) {
			n++
		}
	}
	return n
}

func TestReplayFakeBlockerLeases(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	b := newReplayFakeBlocker(func() time.Time { return now })
	if b.IsBlocked("203.0.113.1") {
		t.Fatal("blocked before any block")
	}
	if outcome, err := b.BlockIPOutcome("203.0.113.1", "r", time.Hour); err != nil || outcome != firewall.BlockOutcomeLive {
		t.Fatalf("first block: %v %v", outcome, err)
	}
	for offset, want := range map[time.Duration]bool{time.Hour - time.Nanosecond: true, time.Hour: false, time.Hour + time.Nanosecond: false} {
		now = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC).Add(offset)
		if got := b.IsBlocked("203.0.113.1"); got != want {
			t.Errorf("IsBlocked at +%v = %v", offset, got)
		}
	}
	now = time.Date(2026, 9, 8, 12, 30, 0, 0, time.UTC)
	if outcome, _ := b.BlockIPOutcome("203.0.113.1", "r", time.Hour); outcome != firewall.BlockOutcomeNoop || !b.IsBlocked("203.0.113.1") ||
		!b.expiry["203.0.113.1"].Equal(time.Date(2026, 9, 8, 13, 0, 0, 0, time.UTC)) {
		t.Fatal("a repeated block renewed the lease or counted as live")
	}
	if b.attempts != 2 || len(b.live) != 1 {
		t.Fatalf("attempts %d, live %d", b.attempts, len(b.live))
	}
	if _, err := b.BlockIPOutcome("203.0.113.2", "r", 0); err != nil || !b.IsBlocked("203.0.113.2") {
		t.Fatal("permanent block not held")
	}
	now = now.Add(1000 * time.Hour)
	if !b.IsBlocked("203.0.113.2") {
		t.Fatal("permanent block expired")
	}
	if err := b.UnblockIP("203.0.113.2"); err != nil || b.IsBlocked("203.0.113.2") || len(b.live) != 2 {
		t.Fatal("unblock kept the entry or erased the call history")
	}
}

var replayT0 = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

// replayHarness runs the real path and the model side by side on one
// virtual clock. The hooks it installs are package globals, so no test using
// it may run in parallel.
type replayHarness struct {
	t     *testing.T
	cfg   *config.Config
	now   time.Time
	fw    *replayFakeBlocker
	cl    *mockIPList
	model *responsereplay.Legacy
}

func newReplayHarness(t *testing.T, capacity int, start time.Time, initial blockState, exempt func(responsereplay.Finding) (responsereplay.ObservedBlock, bool)) *replayHarness {
	t.Helper()
	cfg := pendingTestConfig(t)
	cfg.AutoResponse.MaxBlocksPerHour = capacity
	cfg.AutoResponse.BlockExpiry = "1h"
	cfg.AutoResponse.NetBlock = false
	cfg.AutoResponse.PermBlock = false
	cfg.Challenge.Enabled = true
	h := &replayHarness{t: t, cfg: cfg, now: start}
	previousNow := autoBlockNow
	autoBlockNow = func() time.Time { return h.now }
	t.Cleanup(func() { autoBlockNow = previousNow })
	h.fw = newReplayFakeBlocker(func() time.Time { return h.now })
	applyBlockTestSetup(t, h.fw)
	h.cl = &mockIPList{ips: make(map[string]bool)}
	previousList := GetChallengeIPList()
	SetChallengeIPList(h.cl)
	t.Cleanup(func() { SetChallengeIPList(previousList) })
	if err := writeBlockState(cfg.StatePath, &initial); err != nil {
		t.Fatal(err)
	}
	if exempt == nil {
		exempt = func(responsereplay.Finding) (responsereplay.ObservedBlock, bool) {
			return responsereplay.ObservedBlock{}, false
		}
	}
	classes := responsereplay.Classifier{
		Blockable: func(f responsereplay.Finding) bool {
			return BlockableFinding(fromReplay(f), cfg.AutoResponse.BlockCpanelLogins)
		},
		ChallengeFirst: func(f responsereplay.Finding) bool { return ChallengeRoutesFinding(cfg, fromReplay(f)) },
		SourceIP:       func(f responsereplay.Finding) string { return ExtractIPFromFinding(fromReplay(f)) },
		ExemptBlock:    exempt,
	}
	state := responsereplay.LegacyState{HourKey: initial.HourKey, BlocksThisHour: initial.BlocksThisHour}
	for _, p := range initial.Pending {
		state.Pending = append(state.Pending, responsereplay.PendingEntry{
			Finding: responsereplay.Finding{Check: p.Check, Severity: p.Severity.String(), Message: p.Reason, FindingID: p.FindingID},
			IP:      p.IP, QueuedAt: p.QueuedAt,
		})
	}
	model, err := responsereplay.NewLegacy(responsereplay.LegacyConfig{
		MaxPerHour: capacity, BlockTTL: time.Hour, PendingBound: maxPendingBlocks, PendingMaxAge: maxPendingAge,
		HourLocation: time.UTC, Seed: 1,
	}, classes, state)
	if err != nil {
		t.Fatal(err)
	}
	h.model = model
	return h
}

func toReplay(fs []alert.Finding) []responsereplay.Finding {
	out := make([]responsereplay.Finding, len(fs))
	for i, f := range fs {
		out[i] = responsereplay.Finding{Check: f.Check, Severity: f.Severity.String(), Message: f.Message, Details: f.Details, Ordinal: i + 1}
	}
	return out
}

func fromReplay(f responsereplay.Finding) alert.Finding {
	var sev alert.Severity
	for _, s := range []alert.Severity{alert.Warning, alert.High, alert.Critical} {
		if s.String() == f.Severity {
			sev = s
		}
	}
	return alert.Finding{Check: f.Check, Severity: sev, Message: f.Message, Details: f.Details}
}

type replayStep struct {
	live       []string // addresses the real path newly blocked
	blockMsgs  int      // AUTO-BLOCK findings the real path returned
	warnings   []alert.Finding
	challenged []string
	model      responsereplay.BatchOutcome
}

func (h *replayHarness) run(at time.Time, findings ...alert.Finding) replayStep {
	h.t.Helper()
	h.now = at
	before := len(h.fw.live)
	challengedBefore := len(h.cl.ips)
	challengeActions, blockActions := ChallengeThenBlock(h.cfg, findings)
	var s replayStep
	s.live = slices.Clone(h.fw.live[before:])
	for _, f := range blockActions {
		switch {
		case f.Severity == alert.Critical && strings.HasPrefix(f.Message, "AUTO-BLOCK: "):
			s.blockMsgs++
		case f.Severity == alert.Warning:
			s.warnings = append(s.warnings, f)
		}
	}
	if len(challengeActions) != len(h.cl.ips)-challengedBefore {
		h.t.Fatalf("challenge actions %d, new challenge entries %d", len(challengeActions), len(h.cl.ips)-challengedBefore)
	}
	for ip := range h.cl.ips {
		s.challenged = append(s.challenged, ip)
	}
	slices.Sort(s.challenged)
	out, err := h.model.Step(responsereplay.Batch{At: at, Findings: toReplay(findings)})
	if err != nil {
		h.t.Fatal(err)
	}
	s.model = out
	return s
}

func (h *replayHarness) realState() *blockState { return loadBlockState(h.cfg.StatePath) }

func pendingIPs(ps []pendingIP) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.IP)
	}
	slices.Sort(out)
	return out
}

func modelPendingIPs(ps []responsereplay.PendingEntry) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.IP)
	}
	slices.Sort(out)
	return out
}

func smtpFrom(ip string) alert.Finding {
	return alert.Finding{Check: "smtp_bruteforce", Severity: alert.Critical, Message: "SMTP brute force from " + ip}
}

func docIPs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("2001:db8::%x", i+1)
	}
	return out
}

func smtpBatch(addrs []string) []alert.Finding {
	out := make([]alert.Finding, len(addrs))
	for i, a := range addrs {
		out[i] = smtpFrom(a)
	}
	return out
}

func TestLegacyModelMatchesRealPathUnderCap(t *testing.T) {
	h := newReplayHarness(t, 10, replayT0, blockState{}, nil)
	findings := []alert.Finding{
		smtpFrom("203.0.113.1"), smtpFrom("203.0.113.2"), smtpFrom("203.0.113.3"),
		{Check: "wp_login_bruteforce", Severity: alert.High, Message: "WordPress login brute force from 203.0.113.4"},
		{Check: "wp_login_bruteforce", Severity: alert.High, Message: "WordPress login brute force from 203.0.113.5"},
		{Check: "unregistered_check", Severity: alert.Critical, Message: "noise from 203.0.113.6"},
	}
	hardCount, challengeCount := 0, 0
	for _, f := range findings {
		if BlockableFinding(f, false) && !ChallengeRoutesFinding(h.cfg, f) {
			hardCount++
		}
		if ChallengeRoutesFinding(h.cfg, f) {
			challengeCount++
		}
	}
	if hardCount != 3 || challengeCount != 2 {
		t.Fatalf("fixture routes %d hard and %d challenge findings", hardCount, challengeCount)
	}
	s := h.run(replayT0, findings...)
	wantBlocked := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}
	realBlocked := slices.Sorted(slices.Values(s.live))
	modelBlocked := slices.Sorted(slices.Values(s.model.BlockedIPs))
	if !reflect.DeepEqual(realBlocked, wantBlocked) || !reflect.DeepEqual(modelBlocked, wantBlocked) || s.blockMsgs != 3 {
		t.Fatalf("blocked: real %v (%d findings), model %v", realBlocked, s.blockMsgs, modelBlocked)
	}
	if !reflect.DeepEqual(s.challenged, []string{"203.0.113.4", "203.0.113.5"}) || s.model.ChallengeSkipped != 2 {
		t.Fatalf("challenged: real %v, model skipped %d", s.challenged, s.model.ChallengeSkipped)
	}
	for _, ip := range s.challenged {
		if h.fw.IsBlocked(ip) || h.model.Blocked(ip, replayT0) {
			t.Fatalf("challenged %s was also blocked", ip)
		}
	}
	real, model := h.realState(), h.model.Snapshot()
	if len(real.Pending) != 0 || len(model.Pending) != 0 || real.BlocksThisHour != 3 || model.BlocksThisHour != 3 || real.HourKey != model.HourKey {
		t.Fatalf("state: real %+v, model %+v", real, model)
	}
}

func TestLegacyModelMatchesRealPathOverCapThenDrain(t *testing.T) {
	h := newReplayHarness(t, 10, replayT0, blockState{}, nil)
	addrs := docIPs(12)
	s := h.run(replayT0, smtpBatch(addrs)...)
	real, model := h.realState(), h.model.Snapshot()
	if len(s.live) != 10 || s.model.Blocked != 10 || len(real.Pending) != 2 || len(model.Pending) != 2 ||
		real.BlocksThisHour != 10 || model.BlocksThisHour != 10 {
		t.Fatalf("over cap: real %d blocked %d queued, model %+v", len(s.live), len(real.Pending), s.model)
	}
	// Each implementation's blocked and queued sets partition the twelve;
	// which two wait depends on map order in the live path.
	for name, parts := range map[string][2][]string{
		"real":  {slices.Clone(s.live), pendingIPs(real.Pending)},
		"model": {slices.Clone(s.model.BlockedIPs), modelPendingIPs(model.Pending)},
	} {
		union := slices.Concat(parts[0], parts[1])
		slices.Sort(union)
		if !reflect.DeepEqual(union, slices.Sorted(slices.Values(addrs))) {
			t.Fatalf("%s blocked and queued sets do not partition the candidates: %v", name, union)
		}
	}
	firstReal, firstModel := slices.Clone(s.live), slices.Clone(s.model.BlockedIPs)
	next := h.run(replayT0.Add(time.Hour))
	real, model = h.realState(), h.model.Snapshot()
	if len(next.live) != 2 || next.model.Blocked != 2 || len(real.Pending) != 0 || len(model.Pending) != 0 ||
		real.BlocksThisHour != 2 || model.BlocksThisHour != 2 {
		t.Fatalf("next hour: real %d, model %+v", len(next.live), next.model)
	}
	for _, ip := range firstReal {
		if h.fw.IsBlocked(ip) {
			t.Fatalf("first-hour block %s did not expire", ip)
		}
	}
	for _, ip := range firstModel {
		if h.model.Blocked(ip, h.now) {
			t.Fatalf("model first-hour block %s did not expire", ip)
		}
	}
	all := func(a, b []string) []string {
		u := append(slices.Clone(a), b...)
		slices.Sort(u)
		return slices.Compact(u)
	}
	if len(all(firstReal, next.live)) != 12 || len(all(firstModel, next.model.BlockedIPs)) != 12 {
		t.Fatal("the two hours did not block all twelve candidates once")
	}
}

func TestLegacyModelMatchesRealPathQueueBound(t *testing.T) {
	h := newReplayHarness(t, 10, replayT0, blockState{}, nil)
	h.run(replayT0, smtpBatch(docIPs(10))...)
	fresh := make([]string, maxPendingBlocks+5)
	for i := range fresh {
		fresh[i] = fmt.Sprintf("2001:db8:1::%x", i+1)
	}
	s := h.run(replayT0.Add(time.Minute), smtpBatch(fresh)...)
	real, model := h.realState(), h.model.Snapshot()
	if len(s.live) != 0 || s.model.Blocked != 0 || len(real.Pending) != maxPendingBlocks || len(model.Pending) != maxPendingBlocks || s.model.Overflowed != 5 {
		t.Fatalf("real %d blocked %d queued, model %+v", len(s.live), len(real.Pending), s.model)
	}
	dropped := 0
	for _, w := range s.warnings {
		if strings.Contains(w.Message, "5 dropped (queue full)") {
			dropped++
		}
	}
	if dropped != 1 {
		t.Fatalf("real path did not report exactly five dropped: %+v", s.warnings)
	}
	for name, queued := range map[string][]string{"real": pendingIPs(real.Pending), "model": modelPendingIPs(model.Pending)} {
		if len(slices.Compact(slices.Clone(queued))) != maxPendingBlocks {
			t.Fatalf("%s queue has repeats", name)
		}
		for _, ip := range queued {
			if !slices.Contains(fresh, ip) {
				t.Fatalf("%s queued %s, which was not a new candidate", name, ip)
			}
		}
	}
}

func TestLegacyModelMatchesRealPathAgeBoundary(t *testing.T) {
	evaluation := replayT0.Add(2 * time.Hour)
	queued := pendingIP{IP: "203.0.113.20", Check: "smtp_bruteforce", Severity: alert.Critical, Reason: "SMTP brute force from 203.0.113.20", QueuedAt: replayT0}
	h := newReplayHarness(t, 10, evaluation, blockState{HourKey: evaluation.Format("2006-01-02T15"), BlocksThisHour: 10, Pending: []pendingIP{queued}}, nil)
	if !BlockableFinding(alert.Finding{Check: queued.Check, Severity: queued.Severity}, false) || evaluation.Sub(queued.QueuedAt) != maxPendingAge {
		t.Fatal("fixture is not an eligible entry exactly at the age limit")
	}
	s := h.run(evaluation)
	real, model := h.realState(), h.model.Snapshot()
	if len(real.Pending) != 1 || !real.Pending[0].QueuedAt.Equal(replayT0) || len(model.Pending) != 1 || !model.Pending[0].QueuedAt.Equal(replayT0) || s.model.AgedOut != 0 {
		t.Fatalf("at the limit: real %+v, model %+v", real.Pending, model.Pending)
	}
	s = h.run(evaluation.Add(time.Nanosecond))
	real, model = h.realState(), h.model.Snapshot()
	if len(real.Pending) != 0 || len(model.Pending) != 0 || s.model.AgedOut != 1 || h.fw.attempts != 0 {
		t.Fatalf("past the limit: real %+v, model %+v (%+v), attempts %d", real.Pending, model.Pending, s.model, h.fw.attempts)
	}
}

func TestLegacyModelMatchesRealPathRequeueRefresh(t *testing.T) {
	queued := pendingIP{IP: "203.0.113.30", Check: "smtp_bruteforce", Severity: alert.Critical, Reason: "SMTP brute force from 203.0.113.30", QueuedAt: replayT0}
	at := replayT0.Add(30 * time.Minute)
	h := newReplayHarness(t, 10, at, blockState{HourKey: at.Format("2006-01-02T15"), BlocksThisHour: 10, Pending: []pendingIP{queued}}, nil)
	fresh := alert.Finding{Check: "ftp_bruteforce", Severity: alert.Critical, Message: "FTP brute force from 203.0.113.30"}
	if !BlockableFinding(fresh, false) || ChallengeRoutesFinding(h.cfg, fresh) {
		t.Fatal("refresh fixture is not a hard-block finding")
	}
	s := h.run(at, fresh)
	real, model := h.realState(), h.model.Snapshot()
	if len(real.Pending) != 1 || !real.Pending[0].QueuedAt.Equal(replayT0) || real.Pending[0].Check != fresh.Check || real.Pending[0].Reason != fresh.Message {
		t.Fatalf("real refresh: %+v", real.Pending)
	}
	if len(model.Pending) != 1 || !model.Pending[0].QueuedAt.Equal(replayT0) || model.Pending[0].Finding.Check != fresh.Check || model.Pending[0].Finding.Message != fresh.Message {
		t.Fatalf("model refresh: %+v", model.Pending)
	}
	if len(s.live) != 0 || s.model.Blocked != 0 || s.model.NewCandidates != 0 {
		t.Fatalf("refresh blocked or counted a new candidate: %d %+v", len(s.live), s.model)
	}
}

func TestLegacyModelMatchesRealPathExpiryAndReblock(t *testing.T) {
	h := newReplayHarness(t, 10, replayT0, blockState{}, nil)
	for _, tc := range []struct {
		at   time.Time
		want int
	}{{replayT0, 1}, {replayT0.Add(time.Hour - time.Nanosecond), 0}, {replayT0.Add(time.Hour), 1}} {
		s := h.run(tc.at, smtpFrom("203.0.113.40"))
		if len(s.live) != tc.want || s.model.Blocked != tc.want {
			t.Fatalf("at %v: real %d, model %d", tc.at, len(s.live), s.model.Blocked)
		}
		if h.fw.IsBlocked("203.0.113.40") != h.model.Blocked("203.0.113.40", tc.at) {
			t.Fatalf("membership disagrees at %v", tc.at)
		}
		// Occupancy is what the temporary limit counts: an expired entry
		// the model kept would take a slot the kernel has freed.
		if live, entries := h.fw.liveCount(), len(h.model.Snapshot().Entries); live != entries {
			t.Fatalf("at %v the firewall holds %d blocks, the model %d", tc.at, live, entries)
		}
	}
	if real, model := h.realState(), h.model.Snapshot(); real.BlocksThisHour != 1 || model.BlocksThisHour != 1 || real.HourKey != model.HourKey {
		t.Fatalf("hour reset: real %+v, model %+v", real, model)
	}
}

// A queued entry retries as a block even when its check now routes to the
// challenge; only fresh findings are routed.
func TestLegacyModelMatchesRealPathPendingIsNotRerouted(t *testing.T) {
	queued := pendingIP{IP: "203.0.113.50", Check: "wp_login_bruteforce", Severity: alert.High, Reason: "WordPress login brute force from 203.0.113.50", QueuedAt: replayT0}
	h := newReplayHarness(t, 10, replayT0, blockState{Pending: []pendingIP{queued}}, nil)
	fresh := alert.Finding{Check: "wp_login_bruteforce", Severity: alert.High, Message: "WordPress login brute force from 203.0.113.51"}
	s := h.run(replayT0.Add(time.Minute), fresh)
	if !reflect.DeepEqual(s.live, []string{"203.0.113.50"}) || !reflect.DeepEqual(s.model.BlockedIPs, []string{"203.0.113.50"}) {
		t.Fatalf("queued entry: real %v, model %v", s.live, s.model.BlockedIPs)
	}
	if !reflect.DeepEqual(s.challenged, []string{"203.0.113.51"}) || s.model.ChallengeSkipped != 1 {
		t.Fatalf("fresh finding: real challenged %v, model skipped %d", s.challenged, s.model.ChallengeSkipped)
	}
}

// Blocks from outside the scan path share the firewall but not the budget.
func TestLegacyModelMatchesRealPathExemptBlocks(t *testing.T) {
	const ip = "203.0.113.60"
	observed := alert.Finding{Check: "auto_block", Severity: alert.Critical, Message: "AUTO-BLOCK: " + ip + " blocked (expires in 30m0s)", Details: "Reason: challenge timeout: no solve"}
	exempt := func(f responsereplay.Finding) (responsereplay.ObservedBlock, bool) {
		if f.Check != "auto_block" || !strings.HasPrefix(f.Details, "Reason: challenge timeout: ") {
			return responsereplay.ObservedBlock{}, false
		}
		return responsereplay.ObservedBlock{IP: ip, TTL: 30 * time.Minute}, true
	}
	h := newReplayHarness(t, 10, replayT0, blockState{HourKey: replayT0.Format("2006-01-02T15"), BlocksThisHour: 10}, exempt)
	res, err := ApplyBlock(h.cfg, ApplyBlockRequest{IP: ip, EngineReason: "CSM challenge-timeout: no solve", Reason: "challenge timeout: no solve", TTL: 30 * time.Minute, Source: BlockSourceChallenge})
	if err != nil || res.Outcome != firewall.BlockOutcomeLive || len(h.fw.live) != 1 {
		t.Fatalf("real exempt block: %+v %v", res, err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Message != observed.Message || res.Findings[0].Details != observed.Details {
		t.Fatalf("the model's observation is not what the real path records: %+v", res.Findings)
	}
	// The scan stage then runs with nothing to do.
	_, blockActions := ChallengeThenBlock(h.cfg, nil)
	out, err := h.model.Step(responsereplay.Batch{At: replayT0, Findings: toReplay([]alert.Finding{observed})})
	if err != nil {
		t.Fatal(err)
	}
	real, model := h.realState(), h.model.Snapshot()
	if len(blockActions) != 0 || out.ExemptBlocked != 1 || out.Blocked != 0 || real.BlocksThisHour != 10 || model.BlocksThisHour != 10 {
		t.Fatalf("exempt block used the scan budget: real %+v, model %+v (%+v)", real, model, out)
	}
	for _, at := range []time.Time{replayT0.Add(30*time.Minute - time.Nanosecond), replayT0.Add(30 * time.Minute)} {
		h.now = at
		if h.fw.IsBlocked(ip) != h.model.Blocked(ip, at) {
			t.Fatalf("membership disagrees at %v", at)
		}
	}
}
