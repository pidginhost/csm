//go:build linux

package firewall

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

const (
	leaseBootA = "0f5e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b"
	leaseBootB = "7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d"
)

// bootReading is what the daemon's boot clock reports: the boot and the
// time since it.
type bootReading struct {
	id    string
	since time.Duration
}

func (b *bootReading) read() (string, time.Duration, error) { return b.id, b.since, nil }

func checkpointEngine(dir string, clock *leaseSteps, boot *bootReading) *Engine {
	return &Engine{statePath: dir, cfg: &FirewallConfig{}, leaseClock: clock.read, expiryClock: func() time.Time { return clock.wall }, bootClock: boot.read}
}

func saveLease(t *testing.T, e *Engine) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.saveLeaseLocked(); err != nil {
		t.Fatal(err)
	}
}

func resumeLease(e *Engine) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.resumeLeaseLocked()
}

// The restart contract on one boot: at wall time T, an hour after boot, a
// block has an hour left. Ten minutes later the wall clock is set back an
// hour, and a minute after that the daemon restarts. The block has 49
// minutes left and must be restored for no more.
func TestLeaseCheckpointResumesTheSameBootExactly(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	dir := t.TempDir()
	writeEngineStateFile(t, dir, FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.2", Reason: "auto-block", Source: SourceAutoResponse, BlockedAt: at, ExpiresAt: at.Add(time.Hour)},
	}})
	before := checkpointEngine(dir, &leaseSteps{wall: at, elapsed: at}, &bootReading{id: leaseBootA, since: time.Hour})
	saveLease(t, before)

	restart := &leaseSteps{wall: at.Add(-49 * time.Minute), elapsed: at.Add(-49 * time.Minute)}
	after := checkpointEngine(dir, restart, &bootReading{id: leaseBootA, since: 71 * time.Minute})
	// Restoring the rows resumes the checkpoint first.
	if got := seededTimeouts(t, after); got["203.0.113.2"] != 49*time.Minute {
		t.Fatalf("restored after a step back on the same boot = %v, want 49m", got)
	}
}

// A forward step and its correction between checkpoints: the running
// engine cuts the block short, and the checkpoint saved before the step
// does not know it. The restart restores what the block still has on the
// lease clock: never past its expiry, never longer than it had.
func TestLeaseCheckpointRestoresAForwardStepsBlockOnlyForItsTime(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	dir := t.TempDir()
	writeEngineStateFile(t, dir, FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.2", Reason: "auto-block", Source: SourceAutoResponse, BlockedAt: at, ExpiresAt: at.Add(time.Hour)},
	}})
	clock := &leaseSteps{wall: at, elapsed: at}
	boot := &bootReading{id: leaseBootA, since: time.Hour}
	running := checkpointEngine(dir, clock, boot)
	saveLease(t, running)
	clock.step(2 * time.Hour)
	if got := seededTimeouts(t, running); len(got) != 0 {
		t.Fatalf("after a forward step the running engine restored %v", got)
	}
	clock.step(-2 * time.Hour)
	clock.advance(10 * time.Minute)
	boot.since += 10 * time.Minute
	restart := checkpointEngine(dir, &leaseSteps{wall: clock.wall, elapsed: clock.wall}, boot)
	if got := seededTimeouts(t, restart); got["203.0.113.2"] != 50*time.Minute {
		t.Fatalf("restored after the correction = %v, want the 50m it has left", got)
	}
}

// A new boot proves no downtime: the checkpoint bounds the restart as it
// is, never less.
func TestLeaseCheckpointCreditsNoDowntimeOnANewBoot(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	dir := t.TempDir()
	writeEngineStateFile(t, dir, FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.2", Reason: "auto-block", Source: SourceAutoResponse, BlockedAt: at, ExpiresAt: at.Add(time.Hour)},
	}})
	saveLease(t, checkpointEngine(dir, &leaseSteps{wall: at, elapsed: at}, &bootReading{id: leaseBootA, since: time.Hour}))
	// Longer since this boot than the checkpoint's boot had run: none of
	// it may be credited.
	behind := at.Add(-2 * time.Hour)
	after := checkpointEngine(dir, &leaseSteps{wall: behind, elapsed: behind}, &bootReading{id: leaseBootB, since: 2 * time.Hour})
	if got := seededTimeouts(t, after); got["203.0.113.2"] != time.Hour {
		t.Fatalf("restored on a new boot with the clock behind = %v, want the hour the checkpoint proves", got)
	}
}

// Without a checkpoint the engine keeps the wall clock; a damaged one is
// reported and changes nothing; the lease is resumed once per engine.
func TestLeaseCheckpointMissingOrDamaged(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	for _, content := range []string{"", "{", `{"lease":"2026-03-04T06:06:07Z","boot_id":"` + leaseBootA + `","since_boot":-1}`} {
		dir := t.TempDir()
		if content != "" {
			if err := os.WriteFile(filepath.Join(dir, leaseCheckpointFile), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		e := checkpointEngine(dir, &leaseSteps{wall: at, elapsed: at}, &bootReading{id: leaseBootA, since: time.Hour})
		err := resumeLease(e)
		if (content == "") != (err == nil) {
			t.Fatalf("checkpoint %q: resume error %v", content, err)
		}
		if got := leaseNow(e); !got.Equal(at) {
			t.Fatalf("checkpoint %q moved the clock to %v", content, got)
		}
	}
	dir := t.TempDir()
	saveLease(t, checkpointEngine(dir, &leaseSteps{wall: at.Add(time.Hour), elapsed: at}, &bootReading{id: leaseBootA, since: time.Hour}))
	e := checkpointEngine(dir, &leaseSteps{wall: at, elapsed: at}, &bootReading{id: leaseBootA, since: time.Hour})
	if err := resumeLease(e); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, leaseCheckpointFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := resumeLease(e); err != nil || !leaseNow(e).Equal(at.Add(time.Hour)) {
		t.Fatalf("a second resume read the file again: %v", err)
	}
}

// The checkpoint records the lease clock, not the wall clock, with the
// boot reading taken with it.
func TestLeaseCheckpointRecordsTheLeaseClock(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	dir := t.TempDir()
	clock := &leaseSteps{wall: at, elapsed: at}
	e := checkpointEngine(dir, clock, &bootReading{id: leaseBootA, since: time.Hour})
	leaseNow(e)
	clock.advance(time.Minute)
	clock.step(-time.Hour)
	saveLease(t, e)
	data, err := os.ReadFile(filepath.Join(dir, leaseCheckpointFile))
	if err != nil {
		t.Fatal(err)
	}
	var got leaseCheckpoint
	if err := json.Unmarshal(data, &got); err != nil || !got.Lease.Equal(at.Add(time.Minute)) || got.BootID != leaseBootA || got.SinceBoot != time.Hour {
		t.Fatalf("checkpoint %s, %v", data, err)
	}
}

// A delayed boot read must not pair an earlier lease with a later boot
// instant. Restarting must never restore the sampling delay as new time.
func TestLeaseCheckpointClockPairingDoesNotRenewTime(t *testing.T) {
	for _, delayed := range []string{"save", "resume"} {
		t.Run(delayed, func(t *testing.T) {
			at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
			dir := t.TempDir()
			clock := &leaseSteps{wall: at, elapsed: at}
			boot := &bootReading{id: leaseBootA, since: time.Hour}
			before := checkpointEngine(dir, clock, boot)
			leaseNow(before)
			delay := func() (string, time.Duration, error) {
				id, since, err := boot.read()
				clock.advance(time.Minute)
				clock.step(-time.Hour)
				boot.since += time.Minute
				if delayed == "resume" {
					return id, since, err
				}
				return boot.read()
			}
			if delayed == "save" {
				before.bootClock = delay
			}
			saveLease(t, before)
			clock.step(-time.Hour)
			after := checkpointEngine(dir, clock, boot)
			if delayed == "resume" {
				after.bootClock = delay
			}
			if err := resumeLease(after); err != nil {
				t.Fatal(err)
			}
			if got := leaseNow(after); got.Before(at.Add(time.Minute)) {
				t.Fatalf("%s read delay renewed the lease: %v", delayed, got)
			}
		})
	}
}

func TestLeaseCheckpointAndLedgerFloorCompose(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	for _, bootID := range []string{leaseBootA, leaseBootB} {
		for _, ledger := range []time.Duration{5 * time.Minute, 30 * time.Minute} {
			dir := t.TempDir()
			saveLease(t, checkpointEngine(dir, &leaseSteps{wall: at, elapsed: at}, &bootReading{id: leaseBootA, since: time.Hour}))
			clock := &leaseSteps{wall: at.Add(-time.Hour), elapsed: at}
			e := checkpointEngine(dir, clock, &bootReading{id: bootID, since: time.Hour + 20*time.Minute})
			e.SetLeaseFloor(at.Add(ledger))
			if err := resumeLease(e); err != nil {
				t.Fatal(err)
			}
			want := at.Add(ledger)
			if bootID == leaseBootA && ledger < 20*time.Minute {
				want = at.Add(20 * time.Minute)
			}
			if got := leaseNow(e); !got.Equal(want) {
				t.Fatalf("boot %s ledger %v: lease %v, want %v", bootID, ledger, got, want)
			}
		}
	}
}

func leaseStderr(t *testing.T, run func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	prior := os.Stderr
	defer func() { os.Stderr = prior; _ = w.Close() }()
	os.Stderr = w
	run()
	os.Stderr = prior
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestLeaseCheckpointIOFailuresKeepTheFloorAndReport(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	for _, mode := range []string{"read", "boot", "write"} {
		t.Run(mode, func(t *testing.T) {
			conn, _ := nftConnCapturingRules(t)
			e := newBlockedSetWireTestEngine(t, conn)
			e.listTables = func() ([]*nftables.Table, error) { return nil, nil }
			clock := &leaseSteps{wall: at, elapsed: at}
			e.leaseClock, e.expiryClock = clock.read, func() time.Time { return clock.wall }
			boot := &bootReading{id: leaseBootA, since: time.Hour}
			e.SetBootClock(boot.read)
			saveLease(t, e)
			path := filepath.Join(e.statePath, leaseCheckpointFile)
			if mode == "read" || mode == "write" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				cause := errors.New("fixture boot read failed")
				e.SetBootClock(func() (string, time.Duration, error) { return "", 0, cause })
			}
			e.SetLeaseFloor(at.Add(20 * time.Minute))
			if mode == "write" {
				e.leaseResumed = true
			}
			first := leaseStderr(t, func() {
				if err := e.Apply(); err != nil {
					t.Fatalf("installed ruleset reported failed: %v", err)
				}
			})
			if !strings.Contains(first, "lease checkpoint not saved") || (mode != "write" && !strings.Contains(first, "restoring timed blocks without the lease checkpoint")) {
				t.Fatalf("lost coverage warning: %q", first)
			}
			if got := leaseNow(e); !got.Equal(at.Add(20*time.Minute)) || !e.leaseResumed {
				t.Fatalf("failed resume discarded the floor or retries: %v, resumed=%t", got, e.leaseResumed)
			}
			second := leaseStderr(t, func() {
				if err := e.Apply(); err != nil {
					t.Fatal(err)
				}
			})
			if strings.Contains(second, "restoring timed blocks without") || !strings.Contains(second, "lease checkpoint not saved") {
				t.Fatalf("resume repeated or save not retried: %q", second)
			}
			if mode != "boot" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			e.SetBootClock(boot.read)
			if out := leaseStderr(t, func() {
				if err := e.Apply(); err != nil {
					t.Fatal(err)
				}
			}); out != "" {
				t.Fatalf("repaired checkpoint still warns: %s", out)
			}
			data, err := os.ReadFile(path)
			var ck leaseCheckpoint
			if err != nil || json.Unmarshal(data, &ck) != nil || !ck.Lease.Equal(at.Add(20*time.Minute)) || ck.BootID != leaseBootA {
				t.Fatalf("save did not recover: %s, %v", data, err)
			}
		})
	}
}

// A block authorized during a forward step must not inherit the whole
// step after correction and restart, even if the process dies at intent.
func TestLeaseCheckpointNewBlockDuringForwardStepKeepsAuthorization(t *testing.T) {
	for _, crashAtIntent := range []bool{false, true} {
		conn, _ := nftConnCapturingRules(t)
		e := newBlockedSetWireTestEngine(t, conn)
		at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
		clock := &leaseSteps{wall: at, elapsed: at}
		boot := &bootReading{id: leaseBootA, since: time.Hour}
		e.leaseClock, e.expiryClock = clock.read, func() time.Time { return clock.wall }
		e.SetBootClock(boot.read)
		saveLease(t, e)
		clock.step(2 * time.Hour)
		write := writeFirewallStateJSON
		t.Cleanup(func() { writeFirewallStateJSON = write })
		assertRestart := func() {
			clock.step(-2 * time.Hour)
			clock.advance(10 * time.Minute)
			boot.since += 10 * time.Minute
			after := checkpointEngine(e.statePath, clock, boot)
			if got := seededTimeouts(t, after); len(got) != 1 || got["192.0.2.113"] != 50*time.Minute {
				t.Fatalf("forward-step authorization renewed at restart: %v", got)
			}
		}
		writeFirewallStateJSON = func(path string, mode os.FileMode, v any) error {
			if err := write(path, mode, v); err != nil {
				return err
			}
			if crashAtIntent {
				assertRestart()
			}
			return nil
		}
		if err := e.BlockIPForce("192.0.2.113", "operator", time.Hour); err != nil {
			t.Fatal(err)
		}
		writeFirewallStateJSON = write
		if !crashAtIntent {
			assertRestart()
		}
	}
}

func TestLeaseCheckpointFailureRefusesNewTimedIntent(t *testing.T) {
	conn, captured := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	cause := errors.New("fixture boot clock unavailable")
	e.SetBootClock(func() (string, time.Duration, error) { return "", 0, cause })
	writeRawFirewallState(t, e, FirewallState{})
	err := e.BlockIPForce("192.0.2.113", "operator", time.Hour)
	if !errors.Is(err, cause) || len(*captured) != 0 || len(readRawFirewallState(t, e).Blocked) != 0 {
		t.Fatalf("failed checkpoint admitted a timed block: %v, messages=%d", err, len(*captured))
	}
}

func TestLeaseCheckpointRejectedRulesetDoesNotSave(t *testing.T) {
	conn, err := nftables.New(nftables.WithTestDial(func([]netlink.Message) ([]netlink.Message, error) {
		return nil, syscall.EINVAL
	}))
	if err != nil {
		t.Fatal(err)
	}
	e := newBlockedSetWireTestEngine(t, conn)
	e.listTables = func() ([]*nftables.Table, error) { return nil, nil }
	boot := &bootReading{id: leaseBootA, since: time.Hour}
	e.SetBootClock(boot.read)
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	clock := &leaseSteps{wall: at, elapsed: at}
	e.leaseClock, e.expiryClock = clock.read, func() time.Time { return clock.wall }
	saveLease(t, e)
	path := filepath.Join(e.statePath, leaseCheckpointFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Minute)
	boot.since += time.Minute
	if err = e.Apply(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("missing kernel rejection: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("failed ruleset replaced the checkpoint: %s, %v", after, err)
	}
}
