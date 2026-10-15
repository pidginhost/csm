//go:build linux

package firewall

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func storedBlockedActions(t *testing.T, dir string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored FirewallState
	if err = json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, row := range stored.Blocked {
		out[row.IP] = row.ActionID
	}
	return out
}

// Startup removes the rows of settled attempts (failed, or retired after
// their expiry): nothing they applied can remain. Other rows stay, and a
// repeat changes nothing.
func TestRemoveBlockActionRows(t *testing.T) {
	dir := t.TempDir()
	at := time.Now()
	state := FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.20", Reason: "failed", BlockedAt: at, ExpiresAt: at.Add(30 * 24 * time.Hour), ActionID: "act_failed", Unverified: true},
		{IP: "2001:db8::20", Reason: "retired", BlockedAt: at, ExpiresAt: at.Add(-time.Hour), ActionID: "act_retired", Unverified: true},
		{IP: "203.0.113.21", Reason: "unknown", BlockedAt: at, ExpiresAt: at.Add(time.Hour), ActionID: "act_unknown", Unverified: true},
		{IP: "203.0.113.22", Reason: "applied", BlockedAt: at, ExpiresAt: at.Add(time.Hour), ActionID: "act_applied"},
		{IP: "203.0.113.23", Reason: "operator", BlockedAt: at},
	}}
	writeEngineStateFile(t, dir, state)
	e := &Engine{statePath: dir, cfg: &FirewallConfig{IPv6: true}, expiryClock: func() time.Time { return at }}
	writes := 0
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writeFirewallStateJSON = func(path string, perm os.FileMode, v any) error {
		writes++
		return prev(path, perm, v)
	}
	removed, err := e.RemoveBlockActionRows([]string{"act_failed", "act_retired", "act_missing", ""})
	if err != nil || removed != 2 || writes != 1 {
		t.Fatalf("Remove = %d, %v with %d writes; want 2 rows in one write", removed, err, writes)
	}
	want := map[string]string{"203.0.113.21": "act_unknown", "203.0.113.22": "act_applied", "203.0.113.23": ""}
	if got := storedBlockedActions(t, dir); len(got) != len(want) || got["203.0.113.21"] != want["203.0.113.21"] || got["203.0.113.22"] != want["203.0.113.22"] {
		t.Fatalf("stored rows = %v, want %v", got, want)
	}
	if removed, err = e.RemoveBlockActionRows([]string{"act_failed", "act_retired"}); err != nil || removed != 0 || writes != 1 {
		t.Fatalf("repeat = %d, %v with %d writes; want nothing", removed, err, writes)
	}
	if _, err = (&Engine{statePath: t.TempDir(), cfg: &FirewallConfig{}, lifecycle: &Lifecycle{}}).RemoveBlockActionRows([]string{"act_failed"}); err == nil {
		t.Fatal("removing rows of a durable state succeeded")
	}
}

// A failed write removes nothing: the rows stay held back, unreported, and
// the next start removes them.
func TestRemoveBlockActionRowsWriteFailureKeepsRows(t *testing.T) {
	dir := t.TempDir()
	at := time.Now()
	writeEngineStateFile(t, dir, FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.24", Reason: "failed", BlockedAt: at, ExpiresAt: at.Add(time.Hour), ActionID: "act_failed", Unverified: true},
	}})
	e := &Engine{statePath: dir, cfg: &FirewallConfig{}, expiryClock: func() time.Time { return at }}
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	cause := errors.New("fixture write failure")
	writeFirewallStateJSON = func(string, os.FileMode, any) error { return cause }
	if _, err := e.RemoveBlockActionRows([]string{"act_failed"}); !errors.Is(err, cause) {
		t.Fatalf("Remove error = %v, want the write failure", err)
	}
	if got := storedBlockedActions(t, dir); got["203.0.113.24"] != "act_failed" {
		t.Fatalf("stored rows after a failed write = %v", got)
	}
	if e.IsBlocked("203.0.113.24") {
		t.Fatal("a held row is reported as a block after a failed removal")
	}
}

// Retirement asks the kernel first (spec 5.4, design P7). An attempt is
// clear when its address has no element, or the element belongs to a
// verified row of another action; its own row then goes, in one write for
// the batch. An element still present otherwise keeps it held, as after a
// forward wall step that made its expiry look past.
func TestRetireBlockActionsChecksTheKernel(t *testing.T) {
	f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.60", Reason: "unknown", ActionID: "act_gone", Unverified: true, ExpiresAt: time.Date(2026, 3, 4, 5, 0, 0, 0, time.UTC)},
		{IP: "203.0.113.61", Reason: "unknown", ActionID: "act_held", Unverified: true, ExpiresAt: time.Date(2026, 3, 4, 5, 0, 0, 0, time.UTC)},
		{IP: "203.0.113.62", Reason: "operator", ActionID: "act_operator", ExpiresAt: time.Date(2026, 3, 4, 7, 0, 0, 0, time.UTC)},
		{IP: "2001:db8::63", Reason: "unknown", ActionID: "act_gone6", Unverified: true, ExpiresAt: time.Date(2026, 3, 4, 5, 0, 0, 0, time.UTC)},
	}})
	f.live["203.0.113.61"] = time.Hour
	f.live["203.0.113.62"] = time.Date(2026, 3, 4, 7, 0, 0, 0, time.UTC).Sub(f.at)
	writes := f.countWrites(t)
	members := []BlockAction{
		{Action: "act_gone", IP: "203.0.113.60"},
		{Action: "act_held", IP: "203.0.113.61"},
		{Action: "act_other", IP: "203.0.113.62"},
		{Action: "act_missing", IP: "203.0.113.64"},
		{Action: "act_gone6", IP: "2001:db8::63"},
	}
	clear, err := f.e.RetireBlockActions(members)
	want := []bool{true, false, true, true, true}
	if err != nil || len(clear) != len(want) {
		t.Fatalf("Retire = %v, %v", clear, err)
	}
	for i := range want {
		if clear[i] != want[i] {
			t.Errorf("%s clear = %t, want %t", members[i].Action, clear[i], want[i])
		}
	}
	if *writes != 1 {
		t.Fatalf("retirement made %d state writes, want one", *writes)
	}
	got := storedBlockedActions(t, f.e.statePath)
	if _, ok := got["203.0.113.60"]; ok || got["203.0.113.61"] != "act_held" || got["203.0.113.62"] != "act_operator" {
		t.Fatalf("stored rows = %v; want only the clear attempt's own row gone", got)
	}
	if _, ok := got["2001:db8::63"]; ok {
		t.Fatalf("stored rows = %v; the clear IPv6 row stayed", got)
	}
	// Nothing to remove writes nothing; a failed dump answers nothing.
	if clear, err = f.e.RetireBlockActions(members[3:4]); err != nil || !clear[0] || *writes != 1 {
		t.Fatalf("retire without a row = %v, %v with %d writes", clear, err, *writes)
	}
	f.err = errors.New("fixture dump failure")
	if clear, err = f.e.RetireBlockActions(members[1:2]); err == nil || clear != nil {
		t.Fatalf("retire on a failed dump = %v, %v", clear, err)
	}
}

// Distinct attempts may share an address. Neither ordering may lose the
// clear row's identity, and a matching action at another address stays.
func TestRetireBlockActionsSharedAddress(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{
			{IP: "203.0.113.70", ActionID: "act_own", Unverified: true},
			{IP: "203.0.113.71", ActionID: "act_own", Unverified: true},
		}})
		members := []BlockAction{{Action: "act_own", IP: "203.0.113.70"}, {Action: "act_other", IP: "203.0.113.70"}}
		if reverse {
			members[0], members[1] = members[1], members[0]
		}
		clear, err := f.e.RetireBlockActions(members)
		if err != nil || len(clear) != 2 || !clear[0] || !clear[1] {
			t.Fatalf("retire = %v, %v", clear, err)
		}
		rows := storedBlockedActions(t, f.e.statePath)
		if len(rows) != 1 || rows["203.0.113.71"] != "act_own" {
			t.Fatalf("shared address rows = %v", rows)
		}
	}
}

// A verified flag without a matching kernel timeout does not prove the
// element belongs to the other action.
func TestRetireBlockActionsRequiresMatchingProof(t *testing.T) {
	for _, mismatch := range []string{"unverified", "timeout", "permanent", "missing"} {
		t.Run(mismatch, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			row := BlockedEntry{IP: "203.0.113.72", ActionID: "act_other", ExpiresAt: f.at.Add(time.Hour)}
			f.live[row.IP] = time.Hour
			switch mismatch {
			case "unverified":
				row.Unverified = true
			case "timeout":
				f.live[row.IP] = 2 * time.Hour
			case "permanent":
				f.live[row.IP] = 0
			}
			if mismatch != "missing" {
				writeEngineStateFile(t, f.e.statePath, FirewallState{Blocked: []BlockedEntry{row}})
			}
			clear, err := f.e.RetireBlockActions([]BlockAction{{Action: "act_unknown", IP: row.IP}})
			if err != nil || len(clear) != 1 || clear[0] {
				t.Fatalf("unproven ownership retired the attempt: %v, %v", clear, err)
			}
		})
	}
}

// A failed removal never authorizes ledger retirement, even if rename
// succeeded before its durability error. A retry can safely find no row.
func TestRetireBlockActionsWriteFailure(t *testing.T) {
	for _, renamed := range []bool{false, true} {
		f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{{IP: "203.0.113.73", ActionID: "act_own", Unverified: true}}})
		prev := writeFirewallStateJSON
		cause := errors.New("fixture durability failure")
		writeFirewallStateJSON = func(path string, mode os.FileMode, value any) error {
			if renamed {
				if err := prev(path, mode, value); err != nil {
					return err
				}
			}
			return cause
		}
		t.Cleanup(func() { writeFirewallStateJSON = prev })
		members := []BlockAction{{Action: "act_own", IP: "203.0.113.73"}}
		clear, err := f.e.RetireBlockActions(members)
		writeFirewallStateJSON = prev
		if !errors.Is(err, cause) || clear != nil {
			t.Fatalf("failed write authorized retirement: %v, %v", clear, err)
		}
		rows := storedBlockedActions(t, f.e.statePath)
		if (!renamed && rows["203.0.113.73"] != "act_own") || (renamed && len(rows) != 0) {
			t.Fatalf("failed write rows = %v, renamed %t", rows, renamed)
		}
		if clear, err = f.e.RetireBlockActions(members); err != nil || len(clear) != 1 || !clear[0] {
			t.Fatalf("retry = %v, %v", clear, err)
		}
		if rows = storedBlockedActions(t, f.e.statePath); len(rows) != 0 {
			t.Fatalf("retry left rows = %v", rows)
		}
	}
}

// A restart after removal cannot restore the old row when wall time goes
// backward, even before ledger retirement has committed.
func TestRetireBlockActionsSurvivesRollbackAndRestart(t *testing.T) {
	f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.74", ActionID: "act_unknown", Unverified: true, ExpiresAt: time.Date(2026, 3, 4, 5, 0, 0, 0, time.UTC)},
	}})
	clear, err := f.e.RetireBlockActions([]BlockAction{{Action: "act_unknown", IP: "203.0.113.74"}})
	if err != nil || len(clear) != 1 || !clear[0] {
		t.Fatalf("retire = %v, %v", clear, err)
	}
	behind := f.at.Add(-24 * time.Hour)
	restarted := checkpointEngine(f.e.statePath, &leaseSteps{wall: behind, elapsed: behind}, &bootReading{id: leaseBootA, since: time.Hour})
	if rows := storedBlockedActions(t, f.e.statePath); len(rows) != 0 {
		t.Fatalf("cleanup did not persist: %v", rows)
	}
	if got := seededTimeouts(t, restarted); len(got) != 0 {
		t.Fatalf("rollback restored retired rows: %v", got)
	}
}

// If marking failed before rename, the later removal must carry every
// remaining mark to disk. A fresh engine must still withhold the unknown.
func TestRemoveBlockActionRowsCarriesFailedMarks(t *testing.T) {
	f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.75", ActionID: "act_failed", ExpiresAt: time.Date(2026, 3, 5, 5, 0, 0, 0, time.UTC)},
		{IP: "203.0.113.76", ActionID: "act_unknown", ExpiresAt: time.Date(2026, 3, 5, 5, 0, 0, 0, time.UTC)},
	}})
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writeFirewallStateJSON = func(string, os.FileMode, any) error { return errors.New("fixture mark failure") }
	if _, err := f.e.MarkBlockActionsUnverified([]string{"act_failed", "act_unknown"}); err == nil {
		t.Fatal("marking did not fail")
	}
	writeFirewallStateJSON = prev
	if removed, err := f.e.RemoveBlockActionRows([]string{"act_failed"}); err != nil || removed != 1 {
		t.Fatalf("remove = %d, %v", removed, err)
	}
	rows := storedBlockedActions(t, f.e.statePath)
	if len(rows) != 1 || rows["203.0.113.76"] != "act_unknown" {
		t.Fatalf("removal rows = %v", rows)
	}
	restarted := checkpointEngine(f.e.statePath, &leaseSteps{wall: f.at, elapsed: f.at}, &bootReading{id: leaseBootA, since: time.Hour})
	if got := seededTimeouts(t, restarted); len(got) != 0 {
		t.Fatalf("failed mark was lost at removal: %v", got)
	}
}

// Cleanup identifies rows by canonical address and action together. A
// legacy spelling must not leave a row that a later restart could trust.
func TestRetireBlockActionsAddressForms(t *testing.T) {
	for _, tc := range []struct{ row, target string }{
		{"::ffff:203.0.113.90", "203.0.113.90"},
		{"203.0.113.90", "::ffff:203.0.113.90"},
		{"2001:DB8::90", "2001:db8::90"},
		{"2001:db8::90", "2001:DB8::90"},
		{"2001:db8::90%fixture", "2001:db8::90"},
		{"2001:db8::90", "2001:db8::90%fixture"},
	} {
		t.Run(tc.row+"/"+tc.target, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{
				{IP: tc.row, ActionID: "act_own", Unverified: true},
				{IP: "203.0.113.91", ActionID: "act_own", Unverified: true},
			}})
			clear, err := f.e.RetireBlockActions([]BlockAction{{Action: "act_own", IP: tc.target}})
			if err != nil || len(clear) != 1 || !clear[0] {
				t.Fatalf("retirement = %v, %v", clear, err)
			}
			rows := storedBlockedActions(t, f.e.statePath)
			if len(rows) != 1 || rows["203.0.113.91"] != "act_own" {
				t.Fatalf("cleanup lost address identity: %v", rows)
			}
		})
	}
}

// Neither cleanup may discard the lease proof. A failed read or save
// preserves every row and returns no retirement authorization, on retry too.
func TestRetireBlockActionsRequireLeaseCheckpoint(t *testing.T) {
	for _, operation := range []string{"retire", "remove"} {
		for _, failure := range []string{"boot", "read", "write"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{{IP: "203.0.113.92", ActionID: "act_own", Unverified: true}}})
				boot := &bootReading{id: leaseBootA, since: time.Hour}
				f.e.SetBootClock(boot.read)
				saveLease(t, f.e)
				cause := errors.New("fixture boot clock unavailable")
				if failure == "boot" {
					f.e.SetBootClock(func() (string, time.Duration, error) { return "", 0, cause })
				} else {
					path := filepath.Join(f.e.statePath, leaseCheckpointFile)
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
					f.e.leaseResumed = failure == "write"
				}
				writes := f.countWrites(t)
				for range 2 {
					var err error
					if operation == "retire" {
						var clear []bool
						clear, err = f.e.RetireBlockActions([]BlockAction{{Action: "act_own", IP: "203.0.113.92"}})
						if clear != nil {
							t.Fatalf("unreadable lease authorized retirement: %v", clear)
						}
					} else {
						var removed int
						removed, err = f.e.RemoveBlockActionRows([]string{"act_own"})
						if removed != 0 {
							t.Fatalf("unreadable lease removed %d rows", removed)
						}
					}
					if err == nil || (failure == "boot" && !errors.Is(err, cause)) {
						t.Fatalf("lease failure was lost: %v", err)
					}
					if rows := storedBlockedActions(t, f.e.statePath); len(rows) != 1 || rows["203.0.113.92"] != "act_own" || *writes != 0 {
						t.Fatalf("failed checkpoint changed rows: %v, writes %d", rows, *writes)
					}
				}
			})
		}
	}
}

// A transient resume failure must retry the saved checkpoint, not overwrite
// it from wall time. The resumed clock must also frame ownership proofs.
func TestRetireBlockActionsResumesBeforeProof(t *testing.T) {
	f := newBatchFixture(t, FirewallState{Blocked: []BlockedEntry{{IP: "203.0.113.93", ActionID: "act_other", ExpiresAt: time.Date(2026, 3, 4, 6, 6, 7, 0, time.UTC)}}})
	boot := &bootReading{id: leaseBootA, since: time.Hour}
	f.e.SetBootClock(boot.read)
	floor := f.at.Add(2 * time.Hour)
	f.e.SetLeaseFloor(floor)
	saveLease(t, f.e)
	restart := newBatchFixture(t, FirewallState{})
	restart.e.statePath = f.e.statePath
	restart.live["203.0.113.93"] = time.Hour
	cause := errors.New("fixture boot read unavailable")
	restart.e.SetBootClock(func() (string, time.Duration, error) { return "", 0, cause })
	members := []BlockAction{{Action: "act_unknown", IP: "203.0.113.93"}}
	if clear, err := restart.e.RetireBlockActions(members); !errors.Is(err, cause) || clear != nil {
		t.Fatalf("failed resume = %v, %v", clear, err)
	}
	restart.e.SetBootClock(boot.read)
	clear, err := restart.e.RetireBlockActions(members)
	if err != nil || len(clear) != 1 || clear[0] {
		t.Fatalf("expired other row proved ownership after rollback: %v, %v", clear, err)
	}
	if got := leaseNow(restart.e); got.Before(floor) {
		t.Fatalf("retry discarded the saved lease: %v, want at least %v", got, floor)
	}
}
