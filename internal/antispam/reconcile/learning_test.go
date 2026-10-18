package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/antispam"
)

func learningDesired() Desired {
	d := desired(true)
	d.Settings.Learning, d.Settings.LearningDir = true, antispam.DefaultLearningDir
	return d
}

// After a learning check failure, learning stays off until its
// configuration changes: no reload loop with unchanged failing config.
func TestPassHoldsLearningAfterCheck(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	h.result = antispam.Result{Operation: antispam.OpApply, FailedStep: antispam.LearningCheckStep,
		Rollback: antispam.RollbackVerified, Error: "rspamd's loaded learning configuration could not be verified"}
	r := h.reconciler()
	d := learningDesired()
	r.Pass(context.Background(), d)
	if len(h.requests) != 1 || h.requests[0].Learning == nil || !*h.requests[0].Learning {
		t.Fatalf("first pass requests = %+v, want learning", h.requests)
	}
	h.result = antispam.Result{Operation: antispam.OpApply, OK: true}
	out := r.Pass(context.Background(), d)
	if len(h.requests) != 2 || h.requests[1].Learning != nil {
		t.Fatalf("second pass request = %+v, want core only", h.requests[1])
	}
	held := false
	for _, p := range out.LearningProblems {
		held = held || p.Key == antispam.ReasonApplyFailed
	}
	if !held {
		t.Fatalf("held learning reported no apply_failed problem: %+v", out.LearningProblems)
	}
	// A changed learning configuration lifts the hold.
	other := syntheticKeys()
	other.Prefix = "csmfz_" + strings.Repeat("cd", 16)
	h.keys = &other
	r.Pass(context.Background(), d)
	if len(h.requests) != 3 || h.requests[2].Learning == nil {
		t.Fatalf("changed configuration still held: %+v", h.requests[2])
	}
}

// A learning probe failure (controller or dump unreadable) is retried on
// the next pass with learning still requested.
func TestPassLearningProbeFailureDoesNotHold(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	h.result = antispam.Result{Operation: antispam.OpApply, FailedStep: antispam.LearningProbeStep,
		Rollback: antispam.RollbackVerified, Error: "rspamd's loaded learning configuration could not be read"}
	r := h.reconciler()
	d := learningDesired()
	out := r.Pass(context.Background(), d)
	found := false
	for _, p := range out.LearningProblems {
		found = found || p.Key == antispam.ReasonBackendUnavailable
		if p.Key == antispam.ReasonApplyFailed {
			t.Fatalf("probe failure reported as a hold: %+v", out.LearningProblems)
		}
	}
	if !found || out.LearningGate.Publish {
		t.Fatalf("problems=%+v gate=%+v", out.LearningProblems, out.LearningGate)
	}
	h.result = antispam.Result{Operation: antispam.OpApply, OK: true}
	r.Pass(context.Background(), d)
	if len(h.requests) != 2 || h.requests[1].Learning == nil || !*h.requests[1].Learning {
		t.Fatalf("second pass request = %+v, want learning", h.requests[1])
	}
}

func TestLearningStateNilIsInert(t *testing.T) {
	var st *LearningState
	st.hold("g")
	if st.held("g") {
		t.Fatal("nil state held learning")
	}
}

// An include that did not take effect stays off, with learning on, until
// the learning configuration changes: no reinstall loop.
func TestPassHoldsRoundcubeAfterUnavailable(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	h.result = antispam.Result{Operation: antispam.OpApply, OK: true, Generation: "g",
		Roundcube: antispam.RoundcubeUnavailable + "Roundcube does not load the include's Junk folder"}
	r := h.reconciler()
	d := learningDesired()
	r.Pass(context.Background(), d)
	if h.requests[0].Roundcube == nil || !*h.requests[0].Roundcube {
		t.Fatalf("first request = %+v, want Roundcube", h.requests[0])
	}
	h.result = antispam.Result{Operation: antispam.OpApply, OK: true, Generation: "g"}
	out := r.Pass(context.Background(), d)
	second := h.requests[1]
	if second.Roundcube != nil || second.Learning == nil || !*second.Learning {
		t.Fatalf("second request = %+v, want learning without Roundcube", second)
	}
	reported := false
	for _, p := range out.LearningProblems {
		reported = reported || p.Key == antispam.ReasonRoundcube
	}
	if !reported {
		t.Fatalf("problems = %+v", out.LearningProblems)
	}
}

func TestPassReportsLearningHoldWithoutRepeatedApplies(t *testing.T) {
	h := &fakeHost{assessment: antispam.Assessment{Action: antispam.Keep, Installed: true}}
	r := h.reconciler()
	r.Learning = NewLearningState()
	d := learningDesired()
	r.Learning.hold(learningGeneration(d.Settings))
	for i := 0; i < 2; i++ {
		out := r.Pass(context.Background(), d)
		found := 0
		for _, f := range out.Findings {
			if f.Check == CheckLearning && f.DedupKey == "learning:"+antispam.ReasonApplyFailed {
				found++
			}
		}
		if found != 1 || len(h.requests) != 0 {
			t.Fatalf("held pass: findings=%+v requests=%d", out.Findings, len(h.requests))
		}
	}
}

func TestPassDisablingAntispamClearsLearningHold(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Keep})
	r := h.reconciler()
	d := learningDesired()
	r.Learning.hold(learningGeneration(d.Settings))
	d.Enabled = false
	r.Pass(context.Background(), d)
	d.Enabled = true
	if out := r.Pass(context.Background(), d); len(out.LearningProblems) != 0 {
		t.Fatal("disable and re-enable retained the old learning hold")
	}
}

// learningHost wires learning hooks with a stubbed resolver: tests choose
// the gate; the real resolver has its own tests.
type learningHost struct {
	*fakeHost
	ensureCalls, loadCalls int
	dirs                   []string
	keys                   *antispam.LearningKeys
	ensureErr              error
	created                bool
	resolved               []antispam.HostFacts
	resolve                func(antispam.Settings, antispam.HostFacts) (antispam.Settings, antispam.LearningGate, []antispam.Problem)
}

func syntheticKeys() antispam.LearningKeys {
	b32 := func(seed int) string {
		const alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
		var out strings.Builder
		for i := 0; i < 52; i++ {
			out.WriteByte(alphabet[(i*3+seed*5)%len(alphabet)])
		}
		return out.String()
	}
	return antispam.LearningKeys{
		Fuzzy: antispam.NewSecret(strings.Repeat("8e", 32)), Shingles: antispam.NewSecret(strings.Repeat("9f", 32)),
		Read:   antispam.Keypair{Public: b32(1), Private: antispam.NewSecret(b32(2))},
		Write:  antispam.Keypair{Public: b32(3), Private: antispam.NewSecret(b32(4))},
		Prefix: "csmfz_" + strings.Repeat("ab", 16),
	}
}

func newLearningHost(assessment antispam.Assessment) *learningHost {
	return &learningHost{fakeHost: &fakeHost{assessment: assessment, result: antispam.Result{Operation: antispam.OpApply, OK: true, Generation: "g"}}}
}

func (h *learningHost) reconciler() Reconciler {
	r := h.fakeHost.reconciler()
	r.Learning = NewLearningState()
	r.EnsureKeys = func(_ context.Context, dir string) (bool, error) {
		h.ensureCalls++
		h.dirs = append(h.dirs, dir)
		return h.created, h.ensureErr
	}
	r.LoadKeys = func(string) (antispam.LearningKeys, error) {
		h.loadCalls++
		if h.keys != nil {
			return *h.keys, nil
		}
		return syntheticKeys(), nil
	}
	r.CollectLearning = func(context.Context, *antispam.HostFacts) {}
	r.resolveLearning = func(s antispam.Settings, f antispam.HostFacts) (antispam.Settings, antispam.LearningGate, []antispam.Problem) {
		h.resolved = append(h.resolved, f)
		if h.resolve != nil {
			return h.resolve(s, f)
		}
		s.Roundcube = true
		return s, antispam.LearningGate{Install: true, Publish: true, Roundcube: true}, nil
	}
	return r
}

func learningFindings(out Outcome) map[string]alert.Finding {
	got := map[string]alert.Finding{}
	for _, f := range out.Findings {
		if f.Check == CheckLearning {
			got[strings.TrimPrefix(f.DedupKey, "learning:")] = f
		}
	}
	return got
}

func TestPassInstallsLearning(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	out := h.reconciler().Pass(context.Background(), learningDesired())
	if len(h.requests) != 1 {
		t.Fatalf("requests = %+v", h.requests)
	}
	req := h.requests[0]
	if req.Learning == nil || !*req.Learning || req.Roundcube == nil || !*req.Roundcube || req.LearningDir == nil || *req.LearningDir != antispam.DefaultLearningDir {
		t.Fatalf("request = %+v", req)
	}
	data, _ := json.Marshal(req)
	k := syntheticKeys()
	for _, secret := range []string{k.Fuzzy.Reveal(), k.Shingles.Reveal(), k.Read.Private.Reveal(), k.Write.Private.Reveal(), k.Read.Public, k.Prefix} {
		if strings.Contains(string(data), secret) {
			t.Fatal("the request carries key material")
		}
	}
	if h.ensureCalls != 1 || h.loadCalls != 1 || len(h.resolved) != 1 || h.resolved[0].LearningKeys.Prefix != k.Prefix ||
		h.dirs[0] != antispam.DefaultLearningDir {
		t.Fatalf("ensure=%d load=%d resolved=%d", h.ensureCalls, h.loadCalls, len(h.resolved))
	}
	if out.LearningGate != (antispam.LearningGate{Install: true, Publish: true, Roundcube: true}) || !slices.Contains(out.Checks, CheckLearning) || len(learningFindings(out)) != 0 {
		t.Fatalf("outcome = %+v", out)
	}
}

func TestPassLearningOffRemovesFiles(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	out := h.reconciler().Pass(context.Background(), desired(true))
	if len(h.requests) != 1 || h.requests[0].Learning != nil || h.requests[0].Roundcube != nil {
		t.Fatalf("request = %+v", h.requests)
	}
	if h.ensureCalls != 0 || h.loadCalls != 0 || len(h.resolved) != 0 {
		t.Fatal("learning off still touched keys or ran the resolver")
	}
	if !slices.Contains(out.Checks, CheckLearning) || out.LearningGate != (antispam.LearningGate{}) {
		t.Fatalf("outcome = %+v", out)
	}
	// Antispam off settles the check too, so old learning findings clear.
	h2 := newLearningHost(antispam.Assessment{Action: antispam.Keep})
	if out := h2.reconciler().Pass(context.Background(), desired(false)); !slices.Contains(out.Checks, CheckLearning) {
		t.Fatalf("disabled pass checks = %v", out.Checks)
	}
}

func TestPassDefiniteFailureCoreOnly(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	h.resolve = func(s antispam.Settings, _ antispam.HostFacts) (antispam.Settings, antispam.LearningGate, []antispam.Problem) {
		s.Learning, s.Roundcube = false, false
		return s, antispam.LearningGate{}, []antispam.Problem{{Code: antispam.CodeLearning, Severity: antispam.Warning,
			Key: antispam.ReasonUnsafe, Detail: "the Redis socket carries extra ACL entries"}}
	}
	out := h.reconciler().Pass(context.Background(), learningDesired())
	if len(h.requests) != 1 || h.requests[0].Learning != nil {
		t.Fatalf("request = %+v", h.requests)
	}
	got := learningFindings(out)
	f, ok := got[antispam.ReasonUnsafe]
	if len(got) != 1 || !ok || f.Severity != alert.Warning || !strings.Contains(f.Details, "extra ACL") {
		t.Fatalf("learning findings = %+v", got)
	}
}

func TestPassProbeFailureKeepsInstall(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	h.resolve = func(s antispam.Settings, _ antispam.HostFacts) (antispam.Settings, antispam.LearningGate, []antispam.Problem) {
		return s, antispam.LearningGate{Install: true}, []antispam.Problem{{Code: antispam.CodeLearning, Severity: antispam.Warning,
			Key: antispam.ReasonBackendUnavailable, Detail: "Redis did not answer CSM's read-only checks"}}
	}
	out := h.reconciler().Pass(context.Background(), learningDesired())
	if len(h.requests) != 1 || h.requests[0].Learning == nil || !*h.requests[0].Learning {
		t.Fatalf("request = %+v", h.requests)
	}
	if out.LearningGate.Publish || !out.LearningGate.Install {
		t.Fatalf("gate = %+v", out.LearningGate)
	}
	if _, ok := learningFindings(out)[antispam.ReasonBackendUnavailable]; !ok {
		t.Fatalf("findings = %+v", out.Findings)
	}
}

func TestPassKeysCreatedOnFirstEnable(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	h.created = true
	h.reconciler().Pass(context.Background(), learningDesired())
	if h.ensureCalls != 1 || h.loadCalls != 1 || len(h.resolved) != 1 || h.resolved[0].LearningKeysErr != nil || h.resolved[0].LearningKeys.Fuzzy.Reveal() == "" {
		t.Fatalf("ensure=%d load=%d resolved=%+v", h.ensureCalls, h.loadCalls, h.resolved)
	}
}

func TestPassKeysIncompleteStateMismatch(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	h.ensureErr = errors.New("learning keys are incomplete: missing prefix")
	r := h.reconciler()
	r.resolveLearning = antispam.ResolveLearning
	out := r.Pass(context.Background(), learningDesired())
	if h.loadCalls != 0 {
		t.Fatal("keys were loaded after an incomplete set")
	}
	if len(h.requests) != 1 || h.requests[0].Learning != nil {
		t.Fatalf("request = %+v", h.requests)
	}
	if _, ok := learningFindings(out)[antispam.ReasonStateMismatch]; !ok {
		t.Fatalf("findings = %+v", out.Findings)
	}
}

func TestPassRoundcubeProblemKeepsLearning(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	h.resolve = func(s antispam.Settings, _ antispam.HostFacts) (antispam.Settings, antispam.LearningGate, []antispam.Problem) {
		s.Roundcube = false
		return s, antispam.LearningGate{Install: true, Publish: true}, []antispam.Problem{{Code: antispam.CodeLearning, Severity: antispam.Warning,
			Key: antispam.ReasonRoundcube, Detail: "the webmail Junk-button include cannot be installed or verified"}}
	}
	out := h.reconciler().Pass(context.Background(), learningDesired())
	if req := h.requests[0]; req.Learning == nil || req.Roundcube != nil {
		t.Fatalf("request = %+v", req)
	}
	if _, ok := learningFindings(out)[antispam.ReasonRoundcube]; !ok {
		t.Fatalf("findings = %+v", out.Findings)
	}
}

// Learning is off but rspamd still loads CSM's rules, for example because a
// foreign file replaced one CSM wrote: scoring stays active and is reported.
func TestPassRemovalIncomplete(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Keep, Installed: true})
	collect := func(_ context.Context, _ string) antispam.HostFacts {
		f := goodFeedFacts()
		f.RspamdConfig = antispam.CommandResult{Stdout: `{"fuzzy_check": {"enabled": true, "rule": [{"csm": {}}, {"csm_learn": {}}]}}`}
		return f
	}
	r := h.reconciler()
	r.Collect = collect
	out := r.Pass(context.Background(), desired(true))
	f, ok := learningFindings(out)[antispam.ReasonRemovalIncomplete]
	if !ok || !strings.Contains(f.Details, "still") {
		t.Fatalf("findings = %+v", out.Findings)
	}
	// Once rspamd no longer loads them, the condition clears.
	r.Collect = func(_ context.Context, _ string) antispam.HostFacts {
		f := goodFeedFacts()
		f.RspamdConfig = antispam.CommandResult{Stdout: `{"fuzzy_check": {"enabled": false}}`}
		return f
	}
	if got := learningFindings(r.Pass(context.Background(), desired(true))); len(got) != 0 {
		t.Fatalf("findings after removal = %+v", got)
	}
}

func TestPassBusyKeepsLearningFindings(t *testing.T) {
	h := newLearningHost(antispam.Assessment{Action: antispam.Install})
	h.result = antispam.Result{Operation: antispam.OpApply, Busy: true, FailedStep: "lock", Rollback: antispam.RollbackNone}
	out := h.reconciler().Pass(context.Background(), learningDesired())
	if slices.Contains(out.Checks, CheckLearning) {
		t.Fatalf("busy pass settled learning findings: %v", out.Checks)
	}
}

// The worker's Roundcube report is published in the same pass; only an
// install of the include is held, so a later install can try again.
func TestPassReportsRoundcubeResultImmediately(t *testing.T) {
	for _, operation := range []string{"install", "disable", "remove"} {
		t.Run(operation, func(t *testing.T) {
			h := newLearningHost(antispam.Assessment{Action: antispam.Install})
			h.result = antispam.Result{Operation: antispam.OpApply, OK: true, Generation: "g",
				Roundcube: antispam.RoundcubeUnavailable + "PHP could not verify the include"}
			roundcube := operation != "disable"
			h.resolve = func(s antispam.Settings, _ antispam.HostFacts) (antispam.Settings, antispam.LearningGate, []antispam.Problem) {
				s.Roundcube = roundcube
				return s, antispam.LearningGate{Install: true, Publish: true, Roundcube: roundcube}, nil
			}
			if operation == "remove" {
				h.assessment.Action = antispam.Uninstall
				h.result.Operation, h.result.Generation = antispam.OpRemove, ""
			}
			r := h.reconciler()
			d := learningDesired()
			out := r.Pass(context.Background(), d)
			f, ok := learningFindings(out)[antispam.ReasonRoundcube]
			if !ok || !strings.Contains(f.Details, "PHP could not verify the include") {
				t.Errorf("current pass lost the Roundcube result: %+v", out.Findings)
			}
			s := d.Settings
			s.LearningKeys = syntheticKeys()
			_, held := r.Learning.roundcubeHeld(learningGeneration(s))
			if held != (operation == "install") {
				t.Errorf("Roundcube held=%t after %s", held, operation)
			}
		})
	}
}
