package admissionowner

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/firewall"
)

// A block that returns in its episode after the first one left early
// lasts no longer than the first would have (spec 5.2, 5.4): its member
// ends at the first block's expiry, not a full lifetime from now.
func TestOwnerCapsAReadmissionAtTheFirstBlocksExpiry(t *testing.T) {
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	// The engine's lease clock runs a minute ahead of admission time.
	blocks.lease = func() time.Time { return f.host.now().Add(time.Minute) }
	o := f.start(executeOptions(f, blocks))
	mono := heldMono(t, o)
	first := observe(t, o, p, f, "192.0.2.10", "first-10")
	turn(t, o)
	a := attemptOf(t, o, candidate(t, o, first))
	blocks.set(func(b *fakeBlocks) { b.removed["192.0.2.10"] = true })
	later(t, o, f, mono)
	later(t, o, f, mono)
	if st := ledgerStatus(t, o); st.Effects.General != 0 {
		t.Fatalf("the first block was not marked gone: %+v", st.Effects)
	}
	blocks.set(func(b *fakeBlocks) { b.removed = map[string]bool{} })
	// A turn reads the clock, so the return's root is not in its future.
	later(t, o, f, mono)
	again := observe(t, o, p, f, "192.0.2.10", "again-10")
	turn(t, o)
	c := candidate(t, o, again)
	if c.Key.Episode != candidate(t, o, first).Key.Episode || c.Key.Generation != 2 || c.State != admission.StateVerified {
		t.Fatalf("re-admission = %+v", c)
	}
	_, applies := blocks.calls()
	last := applies[len(applies)-1]
	if len(last) != 1 || last[0].IP != "192.0.2.10" || !last[0].ExpiresAt.Equal(a.ExpiresAt) {
		t.Fatalf("re-admission member %+v, want it to end at the first block's expiry %v", last, a.ExpiresAt)
	}
	if !c.ExpiresAt.Equal(a.ExpiresAt) {
		t.Fatalf("re-admission expiry %v, want %v", c.ExpiresAt, a.ExpiresAt)
	}
}

// A forecast models the same cap: a return to an address whose forecast
// block the session replaced lasts no longer than that block would have.
func TestOwnerForecastCapsAReturnAtItsReplacedBlock(t *testing.T) {
	o, p, f := rotationOwner(t)
	observe(t, o, p, f, "192.0.2.14", "rotate-14")
	turn(t, o)
	fc := forecastOf(t, o)
	if len(fc.answered) != 1 {
		t.Fatalf("answered = %v, want the rotated address", fc.answered)
	}
	var gone string
	var until time.Time
	for ip, at := range fc.answered {
		gone, until = ip, at
	}
	if err := o.do(func() error {
		o.opts.Blocks().(*fakeBlocks).set(func(b *fakeBlocks) { b.limit = 5 })
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	observe(t, o, p, f, gone, "rotate-again")
	turn(t, o)
	fc = forecastOf(t, o)
	if e, ok := fc.entries[gone]; !ok || !e.expires.Equal(until) {
		t.Fatalf("returning forecast block %+v (present %v), want it to end at the replaced block's expiry %v", e, ok, until)
	}
}

// readmissionPick returns a real queued return after a verified block was
// removed. The lease clock leads admission time, including for previews.
func readmissionPick(t *testing.T) (*Owner, *fakeBlocks, *ownerFixture, *fakeMono, execPick, time.Time, *admission.Producer) {
	t.Helper()
	p := withTestRegistry(t)
	f := newOwnerFixture(t)
	blocks := newFakeBlocks()
	blocks.lease = func() time.Time { return f.host.now().Add(time.Minute) }
	opts := executeOptions(f, blocks)
	opts.Expiry = func(admission.Candidate) time.Duration { return 5 * time.Minute }
	o := f.start(opts)
	mono := heldMono(t, o)
	id := observe(t, o, p, f, "192.0.2.10", "first")
	turn(t, o)
	first := candidate(t, o, id)
	if first.State != admission.StateVerified {
		t.Fatalf("first block: %+v", first)
	}
	blocks.set(func(b *fakeBlocks) { b.removed["192.0.2.10"] = true })
	later(t, o, f, mono)
	later(t, o, f, mono)
	later(t, o, f, mono)
	blocks.set(func(b *fakeBlocks) { b.removed = map[string]bool{} })
	id = observe(t, o, p, f, "192.0.2.10", "return")
	c := candidate(t, o, id)
	if c.Key.Episode != first.Key.Episode || c.Key.Generation != 2 || c.State != admission.StateQueued {
		t.Fatalf("queued return: %+v", c)
	}
	return o, blocks, f, mono, execPick{pick: admission.Pick{ID: id, Lane: admission.LaneGeneral, Tier: highTier}, c: c}, first.ExpiresAt, p
}

// Every caller passes the cap in its own clock frame. At the end a
// member is expired, never zero (permanent), and no attempt is charged.
func TestOwnerReadmissionExpiryPaths(t *testing.T) {
	for _, mode := range []string{"execute", "verdict", "forecast", "preview"} {
		for _, expired := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/expired=%t", mode, expired), func(t *testing.T) {
				o, blocks, f, mono, pick, until, _ := readmissionPick(t)
				end := until.Add(-time.Minute)
				if expired {
					delta := end.Sub(f.host.now())
					f.host.advance(delta)
					mono.advance(delta)
					if err := o.do(o.tick); err != nil {
						t.Fatal(err)
					}
					// The engine refuses an expired member. Check the member
					// itself below, so this answer cannot mask a missed cap.
					blocks.set(func(b *fakeBlocks) { b.refuse["192.0.2.10"] = firewall.BlockRefusedExpired })
				}
				used := liveUsed(t, o)
				if err := o.do(func() error {
					switch mode {
					case "execute":
						return o.execute([]execPick{pick})
					case "verdict":
						_, err := o.gateVerdicts(blocks, []execPick{pick}, blocks.LeaseNow())
						return err
					case "forecast":
						if err := o.beginForecast(); err != nil {
							return err
						}
						return o.forecastBlocks([]execPick{pick})
					default:
						return o.preview(pick)
					}
				}); err != nil {
					t.Fatal(err)
				}
				c := candidate(t, o, pick.pick.ID)
				checks, applies := blocks.calls()
				if mode == "preview" {
					if !expired && (c.State != admission.StateObserved || !c.ExpiresAt.Equal(end)) {
						t.Fatalf("preview did not use the admission cap: %+v, want %v", c, end)
					}
				} else {
					members := checks[len(checks)-1]
					if mode != "execute" {
						blocks.mu.Lock()
						members = append([]firewall.BlockMember(nil), blocks.snapshots[len(blocks.snapshots)-1]...)
						blocks.mu.Unlock()
					}
					if len(members) != 1 || members[0].ExpiresAt.IsZero() || !members[0].ExpiresAt.Equal(until) {
						t.Fatalf("%s member %+v, want capped expiry %v", mode, members, until)
					}
				}
				switch {
				case expired:
					if c.Attempts != 0 || !c.State.Terminal() || liveUsed(t, o) != used || len(applies) != 1 {
						t.Fatalf("expired return ran or was charged: %+v, applies %d", c, len(applies))
					}
				case mode == "execute":
					if c.State != admission.StateVerified || len(applies) != 2 || !applies[1][0].ExpiresAt.Equal(until) {
						t.Fatalf("uncapped execution: %+v %+v", c, applies)
					}
				case mode == "forecast":
					fc := forecastOf(t, o)
					if c.State != admission.StateDryRun || !fc.entries["192.0.2.10"].expires.Equal(until) || len(applies) != 1 {
						t.Fatalf("uncapped forecast: %+v %+v", c, fc)
					}
				}
			})
		}
	}
}

// The cap applies only to a later block generation's first attempt;
// shorter lifetimes and retries keep their own deadlines. Another
// episode's row cannot supply the cap, including a row at the same target.
func TestOwnerReadmissionCapScope(t *testing.T) {
	o, _, _, _, pick, until, _ := readmissionPick(t)
	if err := o.do(func() error {
		end := until.Add(-time.Minute)
		lease := o.now.Add(time.Minute)
		other, err := admission.ParseEpisodeID("00000000000000000000000000000001")
		if err != nil || other == pick.c.Key.Episode {
			return fmt.Errorf("invalid other episode fixture: %v", err)
		}
		for _, tc := range []struct {
			name   string
			change func(*admission.Candidate)
			want   time.Time
		}{
			{"later block", func(*admission.Candidate) {}, until},
			{"shorter", func(c *admission.Candidate) { c.PreviewTTL = time.Second }, lease.Add(time.Second)},
			{"retry", func(c *admission.Candidate) { c.Attempts, c.ExpiresAt = 1, lease.Add(time.Hour) }, lease.Add(time.Hour)},
			{"first generation", func(c *admission.Candidate) { c.Key.Generation = 1 }, lease.Add(5 * time.Minute)},
			{"challenge", func(c *admission.Candidate) { c.Key.Kind = admission.KindChallenge }, lease.Add(5 * time.Minute)},
			{"other episode", func(c *admission.Candidate) { c.Key.Episode = other }, lease},
		} {
			c := pick.c
			tc.change(&c)
			if got, capErr := o.cappedExpiry(c, lease); capErr != nil || !got.Equal(tc.want) {
				t.Errorf("%s: expiry %v %v, want %v", tc.name, got, capErr, tc.want)
			}
		}
		for _, at := range []time.Time{end, end.Add(time.Second)} {
			o.now = at
			lease = at.Add(time.Minute)
			if got, capErr := o.cappedExpiry(pick.c, lease); capErr != nil || !got.Equal(lease) || got.IsZero() {
				t.Errorf("no time left: expiry %v %v, want %v", got, capErr, lease)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Advancing the current episode cannot give an older queued return a
// fresh lifetime. The next episode still gets its own ordinary lease.
func TestOwnerReadmissionCannotRenewAfterTheEpisodeAdvances(t *testing.T) {
	o, blocks, f, mono, pick, until, producer := readmissionPick(t)
	delta := until.Add(-time.Minute).Add(time.Second).Sub(f.host.now())
	f.host.advance(delta)
	mono.advance(delta)
	if err := o.do(o.tick); err != nil {
		t.Fatal(err)
	}
	submitObservation(t, o, producer, "192.0.2.10", "next-episode", f.host.now())
	if err := o.do(o.drain); err != nil {
		t.Fatal(err)
	}
	queued := queuedCandidates(t, o)
	if len(queued) != 2 {
		t.Fatalf("want the old return and the next episode queued, got %+v", queued)
	}
	var current admission.Candidate
	for _, c := range queued {
		if c.Key.Episode != pick.c.Key.Episode {
			current = c
		}
	}
	next, err := current.ID()
	if err != nil {
		t.Fatal(err)
	}
	if current.Key.Episode == pick.c.Key.Episode || current.Key.Generation != 1 || candidate(t, o, pick.pick.ID).State != admission.StateQueued {
		t.Fatalf("did not retain an old queued return beside the next episode: %+v", current)
	}
	if err := o.do(func() error {
		lease := blocks.LeaseNow()
		member, err := o.memberOf(pick, lease)
		if err != nil {
			return err
		}
		if !member.ExpiresAt.Equal(lease) || member.ExpiresAt.IsZero() {
			t.Errorf("old return regained a lifetime: %+v, want expiry %v", member, lease)
		}
		return o.preview(pick)
	}); err != nil {
		t.Fatal(err)
	}
	if old := candidate(t, o, pick.pick.ID); old.Attempts != 0 || !old.State.Terminal() {
		t.Fatalf("old return was not refused uncharged: %+v", old)
	}
	turn(t, o)
	if c := candidate(t, o, next); c.State != admission.StateVerified || c.Key.Episode != current.Key.Episode || !c.ExpiresAt.After(until) {
		t.Fatalf("the new episode lost its own lease: %+v", c)
	}
}
