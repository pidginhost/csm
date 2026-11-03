package admissionowner

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// Every first attempt lasts at most the block expiry: a longer selected
// lifetime, such as an incident's week, or a longer configured response is
// cut to it, a shorter one stays short, and a retry keeps its first
// attempt's expiry (spec 5.6). Without a positive block expiry nothing is
// cut.
func TestOwnerLeaseCapsFirstAttempts(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	day, week := 24*time.Hour, 7*24*time.Hour
	fixed := func(d time.Duration) func() time.Duration { return func() time.Duration { return d } }
	preview := func(entry time.Duration, lease func() time.Duration) *Owner {
		return &Owner{opts: Options{Expiry: func(admission.Candidate) time.Duration { return entry }, BlockExpiry: lease}}
	}
	for name, tc := range map[string]struct {
		o    *Owner
		c    admission.Candidate
		want time.Time
	}{
		"a selected week is cut":                 {preview(day, fixed(day)), admission.Candidate{PreviewTTL: week}, now.Add(day)},
		"a longer response is cut":               {preview(2*day, fixed(day)), admission.Candidate{}, now.Add(day)},
		"a shorter request stays short":          {preview(day, fixed(day)), admission.Candidate{PreviewTTL: time.Hour}, now.Add(time.Hour)},
		"the exact block expiry stays":           {preview(day, fixed(day)), admission.Candidate{}, now.Add(day)},
		"a retry keeps its expiry":               {preview(day, fixed(time.Hour)), admission.Candidate{Attempts: 1, ExpiresAt: now.Add(week)}, now.Add(week)},
		"no block expiry cuts nothing":           {preview(week, nil), admission.Candidate{}, now.Add(week)},
		"a zero one cuts nothing":                {preview(week, fixed(0)), admission.Candidate{}, now.Add(week)},
		"a negative cap cuts nothing":            {preview(week, fixed(-time.Hour)), admission.Candidate{}, now.Add(week)},
		"a shorter response stays short":         {preview(time.Minute, fixed(day)), admission.Candidate{}, now.Add(time.Minute)},
		"zero response is not permanent":         {preview(0, fixed(day)), admission.Candidate{}, now},
		"negative response stays expired":        {preview(-time.Hour, fixed(day)), admission.Candidate{}, now.Add(-time.Hour)},
		"negative selected stays expired":        {preview(day, fixed(day)), admission.Candidate{PreviewTTL: -time.Hour}, now.Add(-time.Hour)},
		"largest request is cut before addition": {preview(time.Duration(1<<63-1), fixed(day)), admission.Candidate{}, now.Add(day)},
	} {
		if got := tc.o.expiryOf(tc.c, now); !got.Equal(tc.want) {
			t.Errorf("%s: expiry %v, want %v", name, got, tc.want)
		}
	}
	// An executable owner reads the block expiry of its installed policy.
	exec := &Owner{
		opts:   Options{Blocks: func() BlockEngine { return nil }, BlockExpiry: fixed(week)},
		policy: ExecutionPolicy{Expiry: func(admission.Candidate) time.Duration { return day }, BlockExpiry: time.Hour},
	}
	if got := exec.expiryOf(admission.Candidate{PreviewTTL: week}, now); !got.Equal(now.Add(time.Hour)) {
		t.Fatalf("executable owner expiry %v, want the policy's hour", got)
	}
}

// The lifetime rule has no entry or kind exceptions. This tests expiry
// calculation only; it does not enable service blocks or promotion.
func TestOwnerLeaseCoversEveryEntryAndKind(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for entry := admission.EntryScan; entry.Valid(); entry++ {
		for kind := admission.KindBlockIP; kind.Valid(); kind++ {
			for _, executable := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/engine=%t", entry, kind, executable), func(t *testing.T) {
					o := &Owner{opts: Options{
						Expiry:      func(admission.Candidate) time.Duration { return 7 * 24 * time.Hour },
						BlockExpiry: func() time.Duration { return time.Hour },
					}}
					if executable {
						o.opts.Blocks = func() BlockEngine { return nil }
						o.policy = validPolicy(1)
						o.policy.BlockExpiry = time.Hour
						o.opts.BlockExpiry = func() time.Duration { return 48 * time.Hour }
					}
					for _, selected := range []time.Duration{0, 7 * 24 * time.Hour} {
						c := admission.Candidate{Key: admission.CandidateKey{Kind: kind}, Entry: entry, PreviewTTL: selected}
						if got := o.expiryOf(c, now); !got.Equal(now.Add(time.Hour)) {
							t.Errorf("selected %v: expiry %v, want %v", selected, got, now.Add(time.Hour))
						}
					}
				})
			}
		}
	}
}

// The real preview, forecast and execute callers must pass the capped
// expiry to the ledger, forecast model and engine, including challenges.
func TestOwnerLeaseReachesEveryPath(t *testing.T) {
	for _, mode := range []string{"no engine", "preview", "forecast", "execute"} {
		for _, kind := range []admission.Kind{admission.KindBlockIP, admission.KindChallenge} {
			t.Run(mode+"/"+kind.String(), func(t *testing.T) {
				withLiveExecution(t, mode == "execute")
				producer := withTestRegistry(t)
				f := newOwnerFixture(t)
				blocks := newFakeBlocks()
				opts := previewOptions(f)
				opts.Expiry = func(admission.Candidate) time.Duration { return 7 * 24 * time.Hour }
				opts.BlockExpiry = func() time.Duration { return time.Hour }
				if mode != "no engine" {
					blocks.lease = f.host.now
					opts.Blocks = func() BlockEngine { return blocks }
					policy := validPolicy(1)
					policy.Expiry = opts.Expiry
					policy.BlockExpiry = time.Hour
					policy.DryRun = mode == "forecast"
					opts.Policy = func() ExecutionPolicy { return policy }
					opts.BlockExpiry = func() time.Duration { return 48 * time.Hour }
				}
				o := f.start(opts)
				id, _ := queuedKind(t, o, producer, f.host, admission.SeverityHigh, "192.0.2.10", kind)
				turn(t, o)
				want := f.host.now().Add(time.Hour)
				c := candidate(t, o, id)
				if mode == "forecast" && kind == admission.KindBlockIP {
					fc := forecastOf(t, o)
					if c.State != admission.StateDryRun || fc == nil || len(fc.entries) != 1 || !fc.entries["192.0.2.10"].expires.Equal(want) {
						t.Fatalf("forecast expiry: candidate=%+v forecast=%+v, want %v", c, fc, want)
					}
					blocks.mu.Lock()
					defer blocks.mu.Unlock()
					if len(blocks.snapshots) != 1 || len(blocks.snapshots[0]) != 1 || !blocks.snapshots[0][0].ExpiresAt.Equal(want) || len(blocks.applies) != 0 {
						t.Fatalf("forecast members=%+v applies=%+v, want %v", blocks.snapshots, blocks.applies, want)
					}
					return
				}
				wantState := admission.StateObserved
				if mode == "execute" && kind == admission.KindBlockIP {
					wantState = admission.StateVerified
					checks, applies := blocks.calls()
					if len(checks) != 1 || len(checks[0]) != 1 || !checks[0][0].ExpiresAt.Equal(want) || len(applies) != 1 || len(applies[0]) != 1 || !applies[0][0].ExpiresAt.Equal(want) {
						t.Fatalf("execute members: checks=%+v applies=%+v, want %v", checks, applies, want)
					}
				} else if _, applies := blocks.calls(); len(applies) != 0 {
					t.Fatalf("preview applied members: %+v", applies)
				}
				if c.State != wantState || c.Attempts != 1 || !c.ExpiresAt.Equal(want) {
					t.Fatalf("candidate=%+v, want state %v expiry %v", c, wantState, want)
				}
			})
		}
	}
}

// A published lease changes only at the epoch boundary. Refusing a
// same-epoch edit keeps the installed policy, and a newer epoch recovers.
func TestOwnerLeaseReloadKeepsEarlierExpiries(t *testing.T) {
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	o, reader, _ := policyOwner(t, f, blocks, dryPolicy(1))
	now := f.host.now()
	first := now.Add(24 * time.Hour)
	check := func(want time.Time) {
		t.Helper()
		if err := o.do(func() error {
			if got := o.expiryOf(admission.Candidate{}, now); !got.Equal(want) {
				t.Errorf("new expiry %v, want %v", got, want)
			}
			retry := admission.Candidate{Attempts: 1, ExpiresAt: first}
			if got := o.expiryOf(retry, now.Add(time.Minute)); !got.Equal(first) {
				t.Errorf("retry expiry %v, want original %v", got, first)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	check(first)
	next := dryPolicy(1)
	next.BlockExpiry = time.Hour
	reader.publish(next)
	if err := o.Reload(); !errors.Is(err, ErrPolicy) {
		t.Fatalf("same-epoch lease edit = %v, want ErrPolicy", err)
	}
	check(first)
	next.Epoch = 2
	reader.publish(next)
	if err := o.Reload(); err != nil {
		t.Fatal(err)
	}
	check(now.Add(time.Hour))
}

// An epoch published again with another block expiry is another policy,
// which the owner refuses as it refuses another ceiling.
func TestExecutionPolicySameComparesTheBlockExpiry(t *testing.T) {
	p, q := validPolicy(1), validPolicy(1)
	if !p.same(q) {
		t.Fatal("a repeated policy differs")
	}
	q.BlockExpiry = time.Hour
	if p.same(q) {
		t.Fatal("another block expiry is the same policy")
	}
}

// A policy whose block expiry is not positive is refused: nothing would
// bound the responses it runs.
func TestExecutionPolicyNeedsAPositiveBlockExpiry(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Hour} {
		p := validPolicy(1)
		p.BlockExpiry = d
		if err := p.validate(); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "block expiry") {
			t.Errorf("block expiry %v: validate = %v", d, err)
		}
	}
	if err := validPolicy(1).validate(); err != nil {
		t.Fatalf("a valid policy was refused: %v", err)
	}
}
