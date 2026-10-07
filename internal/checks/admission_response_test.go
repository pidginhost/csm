package checks

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

type respondCall struct {
	kind   admission.Kind
	check  string
	target string
	cursor string
	via    admission.Entry
	// rooted is false for a derived response that had no root to answer.
	rooted bool
}

// fakeAdmission records what the funnels hand admission. Mint returns no
// evidence, so a response names the finding minted just before it by its
// check, target and observation cursor; one with no mint before it had no
// root.
type fakeAdmission struct {
	mu      sync.Mutex
	calls   []respondCall
	refused []string
	refuse  bool
	pending *respondCall
	// mint, when set, returns the evidence Mint hands back.
	mint func(f alert.Finding, target string) admission.Evidence
}

func (a *fakeAdmission) Mint(f alert.Finding, target string) (admission.Evidence, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.refuse {
		return admission.Evidence{}, &admission.Error{Reason: admission.ReasonInvalid, Detail: "refused"}
	}
	a.pending = &respondCall{check: f.Check, target: target, cursor: f.Observation.Cursor, rooted: true}
	if a.mint != nil {
		return a.mint(f, target), nil
	}
	return admission.Evidence{}, nil
}

func (a *fakeAdmission) Refuse(_ admission.Kind, f alert.Finding, _ admission.Entry, _ error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refused = append(a.refused, f.Check)
}

// Respond names a response without a mint before it by the evidence it
// carries: a root minted earlier, or none.
func (a *fakeAdmission) Respond(kind admission.Kind, e admission.Evidence, via admission.Entry, ttl ...time.Duration) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var c respondCall
	switch {
	case a.pending != nil:
		c, a.pending = *a.pending, nil
	case !e.Equal(admission.Evidence{}):
		c = respondCall{check: e.Check(), target: e.Target().Key(), cursor: e.Observation().Cursor, rooted: true}
	}
	c.kind, c.via = kind, via
	a.calls = append(a.calls, c)
	return nil
}

// realRoot mints f's evidence at target as the owner would, with the
// production registry.
func realRoot(t *testing.T, f alert.Finding, target string) admission.Evidence {
	t.Helper()
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	var producer *admission.Producer
	for _, p := range ProducerTable() {
		h, regErr := reg.Register(p.Spec)
		if regErr != nil {
			t.Fatal(regErr)
		}
		if string(h.ID()) == f.Observation.Producer {
			producer = h
		}
	}
	tg, err := AdmissionTarget(target, admission.Caps{})
	if err != nil {
		t.Fatal(err)
	}
	_, in, err := AdmissionEvidence(f, tg)
	if err != nil {
		t.Fatal(err)
	}
	e, err := producer.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (a *fakeAdmission) responses() []respondCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]respondCall(nil), a.calls...)
}

func withAdmission(t *testing.T) *fakeAdmission {
	t.Helper()
	a := &fakeAdmission{}
	prev := getResponseAdmission()
	SetResponseAdmission(a)
	t.Cleanup(func() { SetResponseAdmission(prev) })
	return a
}

func liveAutoBlockConfig(t *testing.T) *config.Config {
	cfg := &config.Config{}
	cfg.StatePath = t.TempDir()
	cfg.AutoResponse.Enabled = true
	cfg.AutoResponse.BlockIPs = true
	setAutoResponseLive(cfg)
	return cfg
}

func withBlocker(t *testing.T) *recordingIPBlocker {
	t.Helper()
	b := &recordingIPBlocker{}
	prev := getIPBlocker()
	SetIPBlocker(b)
	t.Cleanup(func() { SetIPBlocker(prev) })
	return b
}

func withChallengeList(t *testing.T, list ChallengeIPList) {
	t.Helper()
	prev := GetChallengeIPList()
	SetChallengeIPList(list)
	t.Cleanup(func() { SetChallengeIPList(prev) })
}

// Rulings R1 and R4: a block the legacy funnel selects is also handed to
// admission for the address the finding names, whatever the legacy state
// decides next (already blocked, out of hourly budget). Policy gates still
// apply: an ineligible check or an infra address asks for nothing.
func TestAutoBlockAsksAdmissionForTheBlockItSelects(t *testing.T) {
	a := withAdmission(t)
	withBlocker(t)
	withChallengeList(t, nil)
	cfg := liveAutoBlockConfig(t)
	cfg.InfraIPs = []string{"198.51.100.9"}
	cfg.AutoResponse.MaxBlocksPerHour = 1
	findings := []alert.Finding{
		{Check: "pam_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.30", Message: "PAM brute force"},
		{Check: "pam_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.31", Message: "PAM brute force"},
		{Check: "pam_bruteforce", Severity: alert.Critical, SourceIP: "198.51.100.9", Message: "PAM brute force"},
		{Check: "user_outbound_connection", Severity: alert.High, SourceIP: "203.0.113.40", Message: "outbound"},
	}
	AutoBlockIPs(cfg, findings)
	again := []alert.Finding{{Check: "pam_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.30", Message: "PAM brute force"}}
	AutoBlockIPs(cfg, again)
	want := []respondCall{
		{kind: admission.KindBlockIP, check: "pam_bruteforce", target: "203.0.113.30", rooted: true},
		{kind: admission.KindBlockIP, check: "pam_bruteforce", target: "203.0.113.31", rooted: true},
		{kind: admission.KindBlockIP, check: "pam_bruteforce", target: "203.0.113.30", rooted: true},
	}
	if got := a.responses(); !sameResponses(got, want) {
		t.Fatalf("responses = %+v, want %+v", got, want)
	}
}

// A finding the legacy funnel challenges asks admission for a challenge,
// not a block, even when the address is already on the challenge list.
func TestChallengeRouteAsksAdmissionForTheChallenge(t *testing.T) {
	a := withAdmission(t)
	withBlocker(t)
	list := &mockIPList{ips: map[string]bool{"203.0.113.51": true}}
	withChallengeList(t, list)
	cfg := liveAutoBlockConfig(t)
	cfg.Challenge.Enabled = true
	findings := []alert.Finding{
		{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.50", Message: "brute force"},
		{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.51", Message: "brute force"},
	}
	ChallengeThenBlock(cfg, findings)
	want := []respondCall{
		{kind: admission.KindChallenge, check: "wp_login_bruteforce", target: "203.0.113.50", rooted: true},
		{kind: admission.KindChallenge, check: "wp_login_bruteforce", target: "203.0.113.51", rooted: true},
	}
	if got := a.responses(); !sameResponses(got, want) {
		t.Fatalf("responses = %+v, want %+v", got, want)
	}
}

// A challenge-first finding blocks when no challenge list is serving, and
// admission is asked for that block.
func TestAutoBlockAsksForTheBlockWhenNoChallengeServes(t *testing.T) {
	a := withAdmission(t)
	withBlocker(t)
	withChallengeList(t, nil)
	cfg := liveAutoBlockConfig(t)
	cfg.Challenge.Enabled = true
	ChallengeThenBlock(cfg, []alert.Finding{{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.60", Message: "brute force"}})
	want := []respondCall{{kind: admission.KindBlockIP, check: "wp_login_bruteforce", target: "203.0.113.60", rooted: true}}
	if got := a.responses(); !sameResponses(got, want) {
		t.Fatalf("responses = %+v, want %+v", got, want)
	}
}

// One observation reaches IP response once (carried triage): a scan's
// findings are evaluated by the runner, and the dispatcher's later pass
// over the same findings neither blocks again nor asks admission again.
func TestIPResponseRunsOncePerFinding(t *testing.T) {
	a := withAdmission(t)
	b := withBlocker(t)
	withChallengeList(t, nil)
	cfg := liveAutoBlockConfig(t)
	findings := []alert.Finding{{Check: "pam_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.70", Message: "PAM brute force"}}
	ChallengeThenBlock(cfg, findings)
	if !findings[0].AutoIPResponseEvaluated {
		t.Fatal("the evaluated finding is not marked")
	}
	ChallengeThenBlock(cfg, findings)
	AutoBlockIPs(cfg, findings)
	ChallengeRouteIPs(cfg, findings)
	if len(b.calls) != 1 || len(a.responses()) != 1 {
		t.Fatalf("blocks %d, admission responses %d", len(b.calls), len(a.responses()))
	}
}

// A finding admission cannot mint is refused there and counted; the legacy
// block still happens.
func TestLegacyBlockDoesNotWaitForAdmission(t *testing.T) {
	a := withAdmission(t)
	a.refuse = true
	b := withBlocker(t)
	withChallengeList(t, nil)
	AutoBlockIPs(liveAutoBlockConfig(t), []alert.Finding{{Check: "pam_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.80", Message: "PAM brute force"}})
	if len(b.calls) != 1 || len(a.responses()) != 0 || len(a.refused) != 1 || a.refused[0] != "pam_bruteforce" {
		t.Fatalf("blocks %d, admission responses %d, refused %v", len(b.calls), len(a.responses()), a.refused)
	}
}

func sameResponses(got, want []respondCall) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// The challenge stage, too, leaves a finding an earlier pass evaluated:
// the address is not handed to admission a second time.
func TestChallengeRouteRunsOncePerFinding(t *testing.T) {
	a := withAdmission(t)
	withBlocker(t)
	withChallengeList(t, &mockIPList{ips: map[string]bool{}})
	cfg := liveAutoBlockConfig(t)
	cfg.Challenge.Enabled = true
	findings := []alert.Finding{{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.71", Message: "brute force"}}
	ChallengeThenBlock(cfg, findings)
	ChallengeRouteIPs(cfg, findings)
	if got := a.responses(); len(got) != 1 || got[0].kind != admission.KindChallenge {
		t.Fatalf("responses = %+v", got)
	}
}

// Distinct observations in one batch reach admission even when legacy
// routing adds their common address only once.
func TestChallengeBatchAsksAdmissionForEveryObservation(t *testing.T) {
	a := withAdmission(t)
	b := withBlocker(t)
	withChallengeList(t, &mockIPList{ips: map[string]bool{}})
	cfg := liveAutoBlockConfig(t)
	cfg.Challenge.Enabled = true
	findings := []alert.Finding{
		{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.72", Observation: alert.Observation{Cursor: "offset=1"}},
		{Check: "wp_login_bruteforce", Severity: alert.Critical, SourceIP: "203.0.113.72", Observation: alert.Observation{Cursor: "offset=2"}},
	}
	challenges, blocks := ChallengeThenBlock(cfg, findings)
	want := []respondCall{
		{kind: admission.KindChallenge, check: "wp_login_bruteforce", target: "203.0.113.72", cursor: "offset=1", rooted: true},
		{kind: admission.KindChallenge, check: "wp_login_bruteforce", target: "203.0.113.72", cursor: "offset=2", rooted: true},
	}
	if got := a.responses(); !sameResponses(got, want) || len(challenges) != 1 || len(blocks) != 0 || len(b.calls) != 0 {
		t.Fatalf("responses=%+v challenges=%+v blocks=%+v legacy=%+v", got, challenges, blocks, b.calls)
	}
}

func TestAdmissionUsesTheLegacySelectedAddress(t *testing.T) {
	for _, challenged := range []bool{false, true} {
		for _, tc := range []struct {
			name, source, message, want string
		}{
			{"message address", "", "WordPress login brute force from 192.0.2.20: 100 attempts", "192.0.2.20"},
			{"message IPv6", "", "WordPress login brute force from [2001:db8::20]: 100 attempts", "2001:db8::20"},
			{"structured port", "[2001:db8::20]:443", "WordPress login brute force from 192.0.2.21", "2001:db8::20"},
			{"structured precedence", "192.0.2.20", "WordPress login brute force from 192.0.2.21", "192.0.2.20"},
		} {
			t.Run(map[bool]string{false: "block/", true: "challenge/"}[challenged]+tc.name, func(t *testing.T) {
				a := withAdmission(t)
				b := withBlocker(t)
				list := &mockIPList{ips: map[string]bool{}}
				withChallengeList(t, list)
				cfg := liveAutoBlockConfig(t)
				cfg.Challenge.Enabled = challenged
				f := wpBruteForce(tc.source)
				f.Message = tc.message
				challenges, blocks := ChallengeThenBlock(cfg, []alert.Finding{f})
				kind := admission.KindBlockIP
				if challenged {
					kind = admission.KindChallenge
					if len(challenges) != 1 || len(blocks) != 0 || len(b.calls) != 0 || !list.Contains(tc.want) {
						t.Fatalf("legacy challenges=%+v blocks=%+v calls=%+v", challenges, blocks, b.calls)
					}
				} else if len(challenges) != 0 || len(blocks) != 1 || len(b.calls) != 1 || b.calls[0].ip != tc.want {
					t.Fatalf("legacy challenges=%+v blocks=%+v calls=%+v", challenges, blocks, b.calls)
				}
				want := []respondCall{{kind: kind, check: "wp_login_bruteforce", target: tc.want, cursor: "offset=7", rooted: true}}
				if got := a.responses(); !sameResponses(got, want) {
					t.Fatalf("responses=%+v, want %+v", got, want)
				}
			})
		}
	}
}

type failingRecordingBlocker struct{ recordingIPBlocker }

func (b *failingRecordingBlocker) BlockIP(ip, reason string, ttl time.Duration) error {
	_ = b.recordingIPBlocker.BlockIP(ip, reason, ttl)
	return errors.New("firewall unavailable")
}

func TestEvaluatedFindingDoesNotRetryItsPendingBlock(t *testing.T) {
	a := withAdmission(t)
	withChallengeList(t, nil)
	b := &failingRecordingBlocker{}
	prev := getIPBlocker()
	SetIPBlocker(b)
	t.Cleanup(func() { SetIPBlocker(prev) })
	cfg := liveAutoBlockConfig(t)
	findings := []alert.Finding{wpBruteForce("192.0.2.20")}
	ChallengeThenBlock(cfg, findings)
	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 1 || len(b.calls) != 1 {
		t.Fatalf("pending=%+v calls=%+v", state.Pending, b.calls)
	}
	queued := state.Pending[0]
	// Audit identity does not include SourceIP, so a different address can
	// share it when all the finding's text and timestamp fields match.
	state.Pending = append(state.Pending, pendingIP{IP: "192.0.2.21", Check: queued.Check, Severity: alert.Critical, FindingID: queued.FindingID, QueuedAt: queued.QueuedAt})
	saveBlockState(cfg.StatePath, state)
	findings = append(findings, alert.Finding{Check: "auto_response", Message: "scan response"})
	ChallengeThenBlock(cfg, findings)
	if len(b.calls) != 2 || b.calls[1].ip != "192.0.2.21" || len(a.responses()) != 1 {
		t.Fatalf("dispatch retried evaluated work: calls=%+v responses=%+v", b.calls, a.responses())
	}
	state = loadBlockState(cfg.StatePath)
	if len(state.Pending) != 2 {
		t.Fatalf("pending work was lost: %+v", state.Pending)
	}
	for _, p := range state.Pending {
		if p.IP == queued.IP && (p.FindingID != queued.FindingID || !p.QueuedAt.Equal(queued.QueuedAt)) {
			t.Fatalf("pending identity changed: %+v, want %+v", p, queued)
		}
	}
	AutoBlockIPs(cfg, nil)
	if len(b.calls) != 4 {
		t.Fatalf("later retry cycle did not attempt both pending blocks: %+v", b.calls)
	}
}

func TestFreshFindingCanRetryAnEvaluatedAddress(t *testing.T) {
	withAdmission(t)
	withChallengeList(t, nil)
	b := &failingRecordingBlocker{}
	prev := getIPBlocker()
	SetIPBlocker(b)
	t.Cleanup(func() { SetIPBlocker(prev) })
	cfg := liveAutoBlockConfig(t)
	findings := []alert.Finding{wpBruteForce("192.0.2.20")}
	ChallengeThenBlock(cfg, findings)
	state := loadBlockState(cfg.StatePath)
	if len(state.Pending) != 1 {
		t.Fatalf("pending=%+v", state.Pending)
	}
	queued := state.Pending[0]
	fresh := wpBruteForce("192.0.2.20")
	fresh.Timestamp = fresh.Timestamp.Add(time.Second)
	fresh.Observation.Cursor = "offset=8"
	findings = append(findings, fresh)
	ChallengeThenBlock(cfg, findings)
	state = loadBlockState(cfg.StatePath)
	if len(b.calls) != 2 || len(state.Pending) != 1 || state.Pending[0].ActionID != queued.ActionID || !state.Pending[0].QueuedAt.Equal(queued.QueuedAt) {
		t.Fatalf("fresh evidence changed retry identity or duplicated it: calls=%+v pending=%+v", b.calls, state.Pending)
	}
}
