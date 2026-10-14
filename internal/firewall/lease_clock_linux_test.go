//go:build linux

package firewall

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/nftables"
)

// leaseSteps moves the wall clock and the elapsed clock apart, as a step
// of the system clock does.
type leaseSteps struct{ wall, elapsed time.Time }

func (s *leaseSteps) read() (time.Time, time.Time) { return s.wall, s.elapsed }

func (s *leaseSteps) advance(d time.Duration) {
	s.wall, s.elapsed = s.wall.Add(d), s.elapsed.Add(d)
}

func (s *leaseSteps) step(d time.Duration) { s.wall = s.wall.Add(d) }

func leaseNow(e *Engine) time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.leaseNowLocked()
}

func TestLeaseClockNeverRunsBackward(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	clock := &leaseSteps{wall: at, elapsed: at}
	e := &Engine{leaseClock: clock.read}
	if got := leaseNow(e); !got.Equal(at) {
		t.Fatalf("first reading = %v, want %v", got, at)
	}
	clock.step(-time.Hour)
	clock.advance(10 * time.Second)
	if got := leaseNow(e); !got.Equal(at.Add(10 * time.Second)) {
		t.Fatalf("after the wall clock was set back an hour = %v, want the elapsed time", got)
	}
	clock.step(2 * time.Hour)
	if got := leaseNow(e); !got.Equal(at.Add(time.Hour + 10*time.Second)) {
		t.Fatalf("after a forward step = %v, want the wall clock", got)
	}
	clock.step(-time.Hour)
	clock.advance(time.Second)
	if got := leaseNow(e); !got.Equal(at.Add(time.Hour + 11*time.Second)) {
		t.Fatalf("a forward step was given back: %v", got)
	}
}

// A floor ahead of the clock moves it forward; one behind changes nothing.
func TestLeaseFloorOnlyMovesTheClockForward(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	clock := &leaseSteps{wall: at, elapsed: at}
	e := &Engine{leaseClock: clock.read}
	leaseNow(e)
	clock.step(-2 * time.Hour)
	e.SetLeaseFloor(at.Add(-time.Hour))
	if got := leaseNow(e); !got.Equal(at) {
		t.Fatalf("a floor behind the clock moved it: %v", got)
	}
	e.SetLeaseFloor(at.Add(20 * time.Minute))
	clock.advance(time.Second)
	if got := leaseNow(e); !got.Equal(at.Add(20*time.Minute + time.Second)) {
		t.Fatalf("after a floor 20 minutes ahead = %v", got)
	}
}

func seededTimeouts(t *testing.T, e *Engine) map[string]time.Duration {
	t.Helper()
	e.mu.Lock()
	if err := e.resumeLeaseLocked(); err != nil {
		e.mu.Unlock()
		t.Fatal(err)
	}
	initial := e.computeInitialBlockStateLocked()
	e.mu.Unlock()
	out := map[string]time.Duration{}
	for _, elem := range append(initial.blocked4, initial.blocked6...) {
		out[net.IP(elem.Key).String()] = elem.Timeout
	}
	return out
}

// Reapplying the rules after the wall clock is set back restores each
// timed block for the time it had left, never for the step on top.
func TestInitialBlockStateNeverLengthensAfterAWallStep(t *testing.T) {
	for _, durable := range []bool{false, true} {
		at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
		dir := t.TempDir()
		state := FirewallState{Blocked: []BlockedEntry{
			{IP: "203.0.113.2", Reason: "auto-block", Source: SourceAutoResponse, BlockedAt: at, ExpiresAt: at.Add(time.Hour)},
			{IP: "203.0.113.3", Reason: "operator", Source: SourceWebUI, BlockedAt: at},
			{IP: "2001:db8::2", Reason: "auto-block", Source: SourceAutoResponse, BlockedAt: at, ExpiresAt: at.Add(time.Hour)},
			{IP: "2001:db8::3", Reason: "operator", Source: SourceWebUI, BlockedAt: at},
		}}
		writeEngineStateFile(t, dir, state)
		clock := &leaseSteps{wall: at, elapsed: at}
		e := &Engine{statePath: dir, cfg: &FirewallConfig{IPv6: true}, leaseClock: clock.read, expiryClock: func() time.Time { return clock.wall }}
		if durable {
			e.lifecycle = &Lifecycle{Store: committedStateOnlyStore{current: &state}}
		}
		if got := seededTimeouts(t, e); len(got) != 4 || got["203.0.113.2"] != time.Hour || got["2001:db8::2"] != time.Hour || got["203.0.113.3"] != 0 || got["2001:db8::3"] != 0 {
			t.Fatalf("durable %t: first apply = %v", durable, got)
		}
		clock.advance(time.Minute)
		clock.step(-30 * time.Minute)
		if got := seededTimeouts(t, e); len(got) != 4 || got["203.0.113.2"] != 59*time.Minute || got["2001:db8::2"] != 59*time.Minute || got["203.0.113.3"] != 0 || got["2001:db8::3"] != 0 {
			t.Fatalf("durable %t: after the clock was set back 30 minutes = %v, want 59m and permanent", durable, got)
		}
	}
}

// A restart seeds the floor before the first Apply: a clock behind the
// floor restores what was left at the floor, not more.
func TestLeaseFloorBoundsTheFirstApply(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	dir := t.TempDir()
	writeEngineStateFile(t, dir, FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.2", Reason: "auto-block", Source: SourceAutoResponse, BlockedAt: at, ExpiresAt: at.Add(time.Hour)},
		{IP: "203.0.113.4", Reason: "auto-block", Source: SourceAutoResponse, BlockedAt: at, ExpiresAt: at.Add(10 * time.Minute)},
	}})
	clock := &leaseSteps{wall: at, elapsed: at}
	e := &Engine{statePath: dir, cfg: &FirewallConfig{}, leaseClock: clock.read, expiryClock: func() time.Time { return clock.wall }}
	e.SetLeaseFloor(at.Add(20 * time.Minute))
	got := seededTimeouts(t, e)
	if got["203.0.113.2"] != 40*time.Minute {
		t.Fatalf("restored after a floor 20 minutes ahead = %v, want 40m", got)
	}
	if _, restored := got["203.0.113.4"]; restored {
		t.Fatalf("a block that ended before the floor was restored: %v", got)
	}
}

// The batch encodes each member's timeout on the lease clock, at the check
// and again just before the send: a step back during the state write does
// not lengthen it.
func TestApplyBlockBatchTimeoutIgnoresAWallStep(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	clock := &leaseSteps{wall: f.at, elapsed: f.at}
	f.e.leaseClock = clock.read
	f.e.expiryClock = func() time.Time { return clock.wall }
	m := f.member("act_step", "203.0.113.20")
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writeFirewallStateJSON = func(path string, mode os.FileMode, v any) error {
		err := prev(path, mode, v)
		clock.advance(time.Second)
		clock.step(-30 * time.Minute)
		return err
	}
	// The kernel holds what was sent; readback proves the encoded timeout.
	f.onFlush = func() { f.live[m.IP] = time.Hour - time.Second }
	got, err := f.e.ApplyBlockBatch([]BlockMember{m})
	if err != nil || effects(got) != "applied/" {
		t.Fatalf("results %+v, %v: the member was encoded for longer than it had left", got, err)
	}
}

// A member whose expiry passed on the lease clock is refused at the check,
// even when the wall clock was set back before it.
func TestCheckBlockBatchRefusesAnExpiryPassedOnTheLeaseClock(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	clock := &leaseSteps{wall: f.at, elapsed: f.at}
	f.e.leaseClock = clock.read
	f.e.expiryClock = func() time.Time { return clock.wall }
	if _, err := f.e.CheckBlockBatch([]BlockMember{f.member("act_first", "203.0.113.21")}); err != nil {
		t.Fatal(err)
	}
	m := f.member("act_late", "203.0.113.20")
	m.ExpiresAt = f.at.Add(time.Minute)
	clock.advance(2 * time.Minute)
	clock.step(-time.Hour)
	got, err := f.e.CheckBlockBatch([]BlockMember{m})
	if err != nil || len(got) != 1 || got[0] != BlockRefusedExpired {
		t.Fatalf("refusals %v, %v; want expired", got, err)
	}
}

func TestLeaseClockProductionSampleKeepsMonotonicTime(t *testing.T) {
	e := &Engine{}
	first := e.expiryNow()
	if first == first.Round(0) { //nolint:staticcheck // Equal ignores monotonic metadata; struct equality detects its absence.
		t.Fatal("production expiry sample lost its monotonic reading")
	}
	e.leaseAtLocked(first)
	second := e.expiryNow()
	if second == second.Round(0) || e.lease.at != first { //nolint:staticcheck // Equal ignores monotonic metadata; struct equality detects its absence.
		t.Fatal("elapsed subtraction does not retain both production samples")
	}
	want := e.lease.now.Add(second.Sub(first))
	if got := e.leaseAtLocked(second); got.Before(want) {
		t.Fatalf("lease %v is behind elapsed bound %v", got, want)
	}
}

func TestLeaseUndoPreservesAbsoluteExpiryAcrossWallStep(t *testing.T) {
	for _, left := range []time.Duration{time.Hour, 500 * time.Microsecond} {
		conn, captured := nftConnCapturingRules(t)
		e := newBlockedSetWireTestEngine(t, conn)
		at := time.Now().Round(0)
		clock := &leaseSteps{wall: at, elapsed: at}
		e.leaseClock, e.expiryClock = clock.read, func() time.Time { return clock.wall }
		leaseNow(e)
		expected := BlockedEntry{IP: "192.0.2.113", Reason: "replacement", BlockedAt: at}
		prior := BlockedEntry{IP: expected.IP, Reason: "prior", ExpiresAt: at.Add(time.Minute + left)}
		writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{expected}})
		clock.advance(time.Minute)
		clock.step(-time.Hour)
		if err := e.RestoreBlockIfUnchanged(expected.IP, &expected, &prior); err != nil {
			t.Fatal(err)
		}
		got := readRawFirewallState(t, e).Blocked
		timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
		if left < time.Millisecond {
			if len(got) != 0 || len(timeouts) != 0 {
				t.Fatalf("sub-millisecond undo resurrected a block: rows=%v adds=%v", got, timeouts)
			}
		} else if len(got) != 1 || !got[0].ExpiresAt.Equal(prior.ExpiresAt) || len(timeouts) != 1 || timeouts[0] == nil || *timeouts[0] != left {
			t.Fatalf("undo changed deadline or lease: rows=%v adds=%v want=%v", got, timeouts, left)
		}
	}
}

func TestLeaseUndoRefreshesAfterPersistence(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	at := time.Now().Round(0)
	clock := &leaseSteps{wall: at, elapsed: at}
	e.leaseClock, e.expiryClock = clock.read, func() time.Time { return clock.wall }
	expected := BlockedEntry{IP: "192.0.2.113", Reason: "replacement", BlockedAt: at}
	prior := BlockedEntry{IP: expected.IP, Reason: "prior", ExpiresAt: at.Add(time.Hour)}
	writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{expected}})
	write := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = write })
	writeFirewallStateJSON = func(path string, mode os.FileMode, value any) error {
		err := write(path, mode, value)
		clock.advance(time.Minute)
		clock.step(-time.Hour)
		return err
	}
	if err := e.RestoreBlockIfUnchanged(expected.IP, &expected, &prior); err != nil {
		t.Fatal(err)
	}
	timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
	if len(timeouts) != 1 || timeouts[0] == nil || *timeouts[0] != 59*time.Minute {
		t.Fatalf("undo sent stale timeout: %v", timeouts)
	}
	if rows := readRawFirewallState(t, e).Blocked; len(rows) != 1 || !rows[0].ExpiresAt.Equal(prior.ExpiresAt) {
		t.Fatalf("undo moved saved expiry: %+v", rows)
	}
}

func TestLeaseClockNewLegacyBlockUsesLeaseTime(t *testing.T) {
	conn, _ := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	at := time.Now().Round(0)
	clock := &leaseSteps{wall: at, elapsed: at}
	e.leaseClock, e.expiryClock = clock.read, func() time.Time { return clock.wall }
	leaseNow(e)
	clock.step(-time.Hour)
	at = at.Add(time.Hour)
	e.SetLeaseFloor(at)
	if err := e.BlockIPForce("192.0.2.113", "operator", time.Hour); err != nil {
		t.Fatal(err)
	}
	rows := readRawFirewallState(t, e).Blocked
	if len(rows) != 1 || !rows[0].BlockedAt.Equal(at) || !rows[0].ExpiresAt.Equal(at.Add(time.Hour)) {
		t.Fatalf("legacy block mixed clock domains: %+v", rows)
	}
}

func TestLeaseClockDoesNotPruneUntimedAllowState(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	f := newBatchFixture(t, FirewallState{
		Blocked: []BlockedEntry{{IP: "203.0.113.40", ExpiresAt: at.Add(time.Minute)}},
		Allowed: []AllowedEntry{{IP: "203.0.113.41", ExpiresAt: at.Add(time.Minute)}},
	})
	clock := &leaseSteps{wall: at, elapsed: at}
	f.e.leaseClock = clock.read
	f.e.SetLeaseFloor(at.Add(2 * time.Minute))
	f.e.mu.Lock()
	snap, err := f.e.blockSnapshotLocked()
	f.e.mu.Unlock()
	if err != nil || len(snap.state.Blocked) != 0 || len(snap.state.Allowed) != 1 || !snap.allowed["203.0.113.41"] {
		t.Fatalf("lease floor changed untimed allow handling: %+v, %v", snap.state, err)
	}
}

func TestLeaseUndoDoesNotRebaseExpiry(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	at := time.Now().Round(0)
	clock := &leaseSteps{wall: at, elapsed: at}
	reads := 0
	e.leaseClock = func() (time.Time, time.Time) {
		reads++
		if reads == 2 {
			clock.advance(time.Second)
		}
		return clock.read()
	}
	e.expiryClock = func() time.Time { return clock.wall }
	expected := BlockedEntry{IP: "192.0.2.113", Reason: "replacement", BlockedAt: at}
	prior := BlockedEntry{IP: expected.IP, Reason: "prior", ExpiresAt: at.Add(time.Hour)}
	writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{expected}})
	if err := e.RestoreBlockIfUnchanged(expected.IP, &expected, &prior); err != nil {
		t.Fatal(err)
	}
	rows := readRawFirewallState(t, e).Blocked
	timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
	if len(rows) != 1 || !rows[0].ExpiresAt.Equal(prior.ExpiresAt) || len(timeouts) != 1 || timeouts[0] == nil || *timeouts[0] != time.Hour-time.Second {
		t.Fatalf("undo rebased its deadline: rows=%+v timeouts=%v", rows, timeouts)
	}
}

func TestLeaseClockLegacySendRefreshesAfterPersistence(t *testing.T) {
	for _, expired := range []bool{false, true} {
		conn, captured := nftConnCapturingRules(t)
		e := newBlockedSetWireTestEngine(t, conn)
		at := time.Now().Round(0)
		clock := &leaseSteps{wall: at, elapsed: at}
		e.leaseClock, e.expiryClock = clock.read, func() time.Time { return clock.wall }
		write := writeFirewallStateJSON
		t.Cleanup(func() { writeFirewallStateJSON = write })
		writeFirewallStateJSON = func(path string, mode os.FileMode, value any) error {
			err := write(path, mode, value)
			clock.advance(2 * time.Second)
			clock.step(-time.Hour)
			return err
		}
		ttl := time.Hour
		if expired {
			ttl = time.Second
		}
		err := e.BlockIPForce("192.0.2.113", "operator", ttl)
		writeFirewallStateJSON = write
		timeouts := newSetElemTimeouts(t, *captured, "blocked_ips")
		rows := readRawFirewallState(t, e).Blocked
		if expired {
			if err == nil || len(timeouts) != 0 || len(rows) != 0 {
				t.Fatalf("expired legacy send: error=%v timeouts=%v rows=%v", err, timeouts, rows)
			}
		} else if err != nil || len(timeouts) != 1 || timeouts[0] == nil || *timeouts[0] != time.Hour-2*time.Second || len(rows) != 1 || !rows[0].ExpiresAt.Equal(at.Add(time.Hour)) {
			t.Fatalf("legacy send renewed deadline: error=%v timeouts=%v rows=%v", err, timeouts, rows)
		}
	}
}

func TestLeaseClockApplyRefreshesAfterRulesetPreparation(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	e.cfg.IPv6 = true
	at := time.Now().Round(0)
	clock := &leaseSteps{wall: at, elapsed: at}
	e.leaseClock, e.expiryClock = clock.read, func() time.Time { return clock.wall }
	writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{
		{IP: "192.0.2.110", ExpiresAt: at.Add(time.Hour)},
		{IP: "192.0.2.111", ExpiresAt: at.Add(30 * time.Second)},
		{IP: "192.0.2.112"},
		{IP: "2001:db8::110", ExpiresAt: at.Add(time.Hour)},
		{IP: "2001:db8::111", ExpiresAt: at.Add(30 * time.Second)},
		{IP: "2001:db8::112"},
	}})
	e.listTables = func() ([]*nftables.Table, error) {
		clock.advance(time.Minute)
		clock.step(-time.Hour)
		return nil, nil
	}
	if err := e.Apply(); err != nil {
		t.Fatal(err)
	}
	for _, set := range []string{"blocked_ips", "blocked_ips6"} {
		timeouts := newSetElemTimeouts(t, *captured, set)
		if len(timeouts) != 2 || timeouts[0] == nil || *timeouts[0] != 59*time.Minute || timeouts[1] != nil {
			t.Fatalf("%s renewed or made an expired row permanent: %v", set, timeouts)
		}
	}
}
