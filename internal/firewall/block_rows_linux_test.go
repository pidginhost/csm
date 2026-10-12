//go:build linux

package firewall

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func unverifiedRowsState(at time.Time) FirewallState {
	return FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.10", Reason: "applied", BlockedAt: at, ExpiresAt: at.Add(time.Hour), ActionID: "act_applied"},
		{IP: "203.0.113.11", Reason: "unknown", BlockedAt: at, ExpiresAt: at.Add(time.Hour), ActionID: "act_unknown", Unverified: true},
		{IP: "2001:db8::11", Reason: "unknown", BlockedAt: at, ExpiresAt: at.Add(time.Hour), ActionID: "act_unknown6", Unverified: true},
		{IP: "203.0.113.12", Reason: "operator", BlockedAt: at},
	}}
}

func TestUnverifiedBlockRowsAreNotReportedOrRestored(t *testing.T) {
	dir := t.TempDir()
	at := time.Now()
	writeEngineStateFile(t, dir, unverifiedRowsState(at))
	e := &Engine{statePath: dir, cfg: &FirewallConfig{IPv6: true}, expiryClock: func() time.Time { return at }}

	for ip, want := range map[string]bool{"203.0.113.10": true, "203.0.113.11": false, "2001:db8::11": false, "203.0.113.12": true} {
		if got := e.IsBlocked(ip); got != want {
			t.Errorf("IsBlocked(%s) = %t, want %t", ip, got, want)
		}
	}
	if got := e.BlockedCount(); got != 2 {
		t.Errorf("BlockedCount = %d, want 2", got)
	}
	if got := e.RuleCounts().Blocked; got != 2 {
		t.Errorf("RuleCounts.Blocked = %d, want 2", got)
	}
	if got := e.Status()["blocked"]; got != 2 {
		t.Errorf("Status blocked = %v, want 2", got)
	}

	e.mu.Lock()
	initial := e.computeInitialBlockStateLocked()
	e.mu.Unlock()
	var seeded []string
	for _, elem := range append(initial.blocked4, initial.blocked6...) {
		seeded = append(seeded, net.IP(elem.Key).String())
	}
	if strings.Join(seeded, ",") != "203.0.113.10,203.0.113.12" {
		t.Fatalf("seeded %v, want the applied and the operator rows only", seeded)
	}
}

func TestBlockedEntryActionFieldsAreOptional(t *testing.T) {
	legacy, err := json.Marshal(BlockedEntry{IP: "203.0.113.12", Reason: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(legacy), "action_id") || strings.Contains(string(legacy), "unverified") {
		t.Fatalf("a row without an action writes the new fields: %s", legacy)
	}
	var back BlockedEntry
	data, err := json.Marshal(BlockedEntry{IP: "203.0.113.11", ActionID: "act_unknown", Unverified: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.ActionID != "act_unknown" || !back.Unverified {
		t.Fatalf("round trip = %+v from %s", back, data)
	}
}

func TestMarkBlockActionsUnverified(t *testing.T) {
	dir := t.TempDir()
	at := time.Now()
	state := unverifiedRowsState(at)
	state.Blocked[1].Unverified = false
	writeEngineStateFile(t, dir, state)
	e := &Engine{statePath: dir, cfg: &FirewallConfig{IPv6: true}}

	writes := 0
	prev := writeFirewallStateJSON
	t.Cleanup(func() { writeFirewallStateJSON = prev })
	writeFirewallStateJSON = func(path string, perm os.FileMode, v any) error {
		writes++
		return prev(path, perm, v)
	}

	marked, err := e.MarkBlockActionsUnverified([]string{"act_unknown", "act_unknown6", "act_missing"})
	if err != nil || marked != 1 || writes != 1 {
		t.Fatalf("Mark = %d, %v with %d writes; want 1 row, one write", marked, err, writes)
	}
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored FirewallState
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	flags := map[string]bool{}
	for _, row := range stored.Blocked {
		flags[row.IP] = row.Unverified
	}
	if !flags["203.0.113.11"] || !flags["2001:db8::11"] || flags["203.0.113.10"] || flags["203.0.113.12"] {
		t.Fatalf("stored flags = %v", flags)
	}
	if e.IsBlocked("203.0.113.11") {
		t.Fatal("a marked row is still reported as blocked")
	}

	for _, ids := range [][]string{{"act_unknown"}, nil, {""}} {
		if marked, err := e.MarkBlockActionsUnverified(ids); err != nil || marked != 0 || writes != 1 {
			t.Fatalf("Mark(%q) = %d, %v with %d writes; want nothing changed or written", ids, marked, err, writes)
		}
	}
}

func TestMarkBlockActionsUnverifiedRefusesDurableState(t *testing.T) {
	e := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{}, lifecycle: &Lifecycle{}}
	if _, err := e.MarkBlockActionsUnverified([]string{"act_unknown"}); err == nil {
		t.Fatal("marking rows of a durable state succeeded")
	}
}

func TestUnverifiedDuplicateWinsNormalization(t *testing.T) {
	at := time.Now()
	ordinary := BlockedEntry{IP: "::ffff:203.0.113.11", Reason: "operator", ExpiresAt: at.Add(2 * time.Hour)}
	unknown := BlockedEntry{IP: "203.0.113.11", Reason: "unknown", ActionID: "act_unknown", Unverified: true, ExpiresAt: at.Add(time.Hour)}
	for _, reverse := range []bool{false, true} {
		t.Run(map[bool]string{false: "marked_first", true: "ordinary_first"}[reverse], func(t *testing.T) {
			rows := []BlockedEntry{unknown, ordinary}
			if reverse {
				rows[0], rows[1] = rows[1], rows[0]
			}
			e := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{IPv6: true}, expiryClock: func() time.Time { return at }}
			state := FirewallState{Blocked: rows}
			if err := e.saveState(&state); err != nil {
				t.Fatal(err)
			}
			got := e.loadStateFile()
			if len(got.Blocked) != 1 || !got.Blocked[0].Unverified || got.Blocked[0].ActionID != unknown.ActionID || !got.Blocked[0].ExpiresAt.Equal(unknown.ExpiresAt) {
				t.Fatalf("normalized rows = %+v, want the marked attempt", got.Blocked)
			}
			if e.IsBlocked(unknown.IP) || e.BlockedCount() != 0 || e.Status()["blocked"] != 0 {
				t.Fatal("normalization reported an unverified duplicate as a block")
			}
			e.mu.Lock()
			initial := e.computeInitialBlockStateLocked()
			e.mu.Unlock()
			if len(initial.blocked4) != 0 || len(initial.blocked6) != 0 {
				t.Fatal("normalization seeded an unverified duplicate")
			}
		})
	}
}

func TestMarkUnverifiedBeforeDuplicateNormalization(t *testing.T) {
	at := time.Now()
	for _, reverse := range []bool{false, true} {
		t.Run(map[bool]string{false: "named_first", true: "ordinary_first"}[reverse], func(t *testing.T) {
			rows := []BlockedEntry{
				{IP: "203.0.113.11", ActionID: "act_unknown", ExpiresAt: at.Add(time.Hour)},
				{IP: "::ffff:203.0.113.11", Reason: "operator", ExpiresAt: at.Add(2 * time.Hour)},
			}
			if reverse {
				rows[0], rows[1] = rows[1], rows[0]
			}
			dir := t.TempDir()
			writeEngineStateFile(t, dir, FirewallState{Blocked: rows})
			e := &Engine{statePath: dir, cfg: &FirewallConfig{IPv6: true}, expiryClock: func() time.Time { return at }}
			if marked, err := e.MarkBlockActionsUnverified([]string{"act_unknown"}); err != nil || marked != 1 {
				t.Fatalf("Mark = %d, %v; want the named raw row marked", marked, err)
			}
			stored, ok := e.loadStateFileRawLocked()
			if !ok || len(stored.Blocked) != 1 || !stored.Blocked[0].Unverified || stored.Blocked[0].ActionID != "act_unknown" {
				t.Fatalf("stored rows = %+v, readable = %t", stored.Blocked, ok)
			}
		})
	}
}

func TestUnverifiedRowsSurviveUnrelatedUpsertAndExpiry(t *testing.T) {
	at := time.Now()
	e := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{IPv6: true}, expiryClock: func() time.Time { return at }}
	state := FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.11", ActionID: "act_unknown", Unverified: true, ExpiresAt: at.Add(time.Hour)},
		{IP: "203.0.113.12", ExpiresAt: at.Add(-time.Second)},
	}}
	upsertBlockedEntryInState(&state, BlockedEntry{IP: "203.0.113.13", Reason: "operator"})
	pruned, dropped := pruneBlocked(state.Blocked, at)
	if !dropped || len(pruned) != 2 {
		t.Fatalf("pruning = %+v, dropped = %t", pruned, dropped)
	}
	state.Blocked = pruned
	if err := e.saveState(&state); err != nil {
		t.Fatal(err)
	}
	e.clearStateCacheLocked()
	got := e.loadStateFile()
	row, ok := blockedStateEntry(got, "203.0.113.11")
	if !ok || !row.Unverified || row.ActionID != "act_unknown" || !row.ExpiresAt.Equal(at.Add(time.Hour)) {
		t.Fatalf("active unverified row = %+v, present = %t", row, ok)
	}
	if e.IsBlocked(row.IP) || e.BlockedCount() != 1 || e.Status()["blocked"] != 1 {
		t.Fatal("an unrelated upsert or expiry changed the marked row's visibility")
	}
	e.expiryClock = func() time.Time { return at.Add(time.Hour) }
	got = e.loadStateFile()
	row, ok = blockedStateEntry(got, "203.0.113.11")
	if len(got.Blocked) != 2 || !ok || !row.Unverified || row.ActionID != "act_unknown" || !row.ExpiresAt.Equal(at.Add(time.Hour)) {
		t.Fatalf("rows at the marked row's expiry = %+v", got.Blocked)
	}
	if err := e.saveState(&got); err != nil {
		t.Fatal(err)
	}
	e.clearStateCacheLocked()
	if got := e.loadStateFile(); len(got.Blocked) != 2 || e.IsBlocked("203.0.113.11") || e.BlockedCount() != 1 {
		t.Fatalf("saved rows at the marked row's expiry = %+v", got.Blocked)
	}
}

func TestExpiredUnverifiedRowsStayUntilMatchingRetirement(t *testing.T) {
	at := time.Now().UTC()
	unknown := BlockedEntry{IP: "203.0.113.11", ActionID: "act_unknown", Unverified: true, ExpiresAt: at.Add(-time.Hour)}
	pruned, dropped := pruneBlocked([]BlockedEntry{unknown}, at)
	if dropped || len(pruned) != 1 || !SameBlockedEntry(pruned[0], unknown) {
		t.Fatalf("pruning only an expired unknown = %+v, dropped = %t", pruned, dropped)
	}
	pruned, dropped = pruneBlocked([]BlockedEntry{unknown, {IP: "203.0.113.12", ExpiresAt: at.Add(-time.Second)}}, at)
	if !dropped || len(pruned) != 1 || !SameBlockedEntry(pruned[0], unknown) {
		t.Fatalf("pruning expired ordinary and unknown rows = %+v, dropped = %t", pruned, dropped)
	}
	root := t.TempDir()
	dir := filepath.Join(root, "firewall")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	e := &Engine{statePath: dir, cfg: &FirewallConfig{IPv6: true}, expiryClock: func() time.Time { return at }}
	state := FirewallState{Blocked: []BlockedEntry{unknown}}
	if err := e.saveState(&state); err != nil {
		t.Fatal(err)
	}
	e.clearStateCacheLocked()
	got := e.loadStateFile()
	if len(got.Blocked) != 1 || !SameBlockedEntry(got.Blocked[0], unknown) {
		t.Fatalf("expired unknown cache row = %+v", got.Blocked)
	}
	if e.IsBlocked(unknown.IP) || e.BlockedCount() != 0 || e.RuleCounts().Blocked != 0 || e.Status()["blocked"] != 0 {
		t.Fatal("an expired unknown was reported as an enforced block")
	}
	e.mu.Lock()
	initial := e.computeInitialBlockStateLocked()
	e.mu.Unlock()
	if len(initial.blocked4) != 0 || len(initial.blocked6) != 0 {
		t.Fatal("an expired unknown was seeded")
	}
	public, err := LoadState(root)
	if err != nil || len(public.Blocked) != 1 || !SameBlockedEntry(public.Blocked[0], unknown) {
		t.Fatalf("public load = %+v, %v; want the expired unknown", public, err)
	}
	scans := e.expiryScans
	for range 3 {
		_ = e.loadStateFile()
		_ = e.IsBlocked(unknown.IP)
		_ = e.BlockedCount()
	}
	if e.expiryScans != scans {
		t.Fatalf("expired unknown caused repeated expiry scans: %d -> %d", scans, e.expiryScans)
	}
	upsertBlockedEntryInState(&got, BlockedEntry{IP: "203.0.113.13", Reason: "operator"})
	if saveErr := e.saveState(&got); saveErr != nil {
		t.Fatal(saveErr)
	}
	e.clearStateCacheLocked()
	got = e.loadStateFile()
	row, ok := blockedStateEntry(got, unknown.IP)
	if len(got.Blocked) != 2 || !ok || !SameBlockedEntry(row, unknown) || e.IsBlocked(unknown.IP) || e.BlockedCount() != 1 {
		t.Fatalf("unrelated saved rows = %+v", got.Blocked)
	}
	public, err = LoadState(root)
	if err != nil {
		t.Fatal(err)
	}
	row, ok = blockedStateEntry(*public, unknown.IP)
	if len(public.Blocked) != 2 || !ok || !SameBlockedEntry(row, unknown) {
		t.Fatalf("public load after unrelated save = %+v", public.Blocked)
	}
	// After owner settlement, explicit cleanup must not resurrect the row.
	removeBlockedIPFromState(&got, unknown.IP)
	if saveErr := e.saveState(&got); saveErr != nil {
		t.Fatal(saveErr)
	}
	e.clearStateCacheLocked()
	got = e.loadStateFile()
	if len(got.Blocked) != 1 || got.Blocked[0].IP != "203.0.113.13" || e.BlockedCount() != 1 {
		t.Fatalf("rows after matching retirement = %+v", got.Blocked)
	}
}

func TestMarkUnverifiedWriteFailureKeepsSafetyAcrossReload(t *testing.T) {
	for _, afterRename := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_rename", true: "after_rename"}[afterRename], func(t *testing.T) {
			at := time.Now()
			dir := t.TempDir()
			writeEngineStateFile(t, dir, FirewallState{Blocked: []BlockedEntry{{IP: "203.0.113.11", ActionID: "act_unknown", ExpiresAt: at.Add(time.Hour)}}})
			e := &Engine{statePath: dir, cfg: &FirewallConfig{IPv6: true}, expiryClock: func() time.Time { return at }}
			prev := writeFirewallStateJSON
			t.Cleanup(func() { writeFirewallStateJSON = prev })
			cause := errors.New("state write refused")
			writeFirewallStateJSON = func(path string, perm os.FileMode, v any) error {
				if afterRename {
					if err := prev(path, perm, v); err != nil {
						return err
					}
				}
				return cause
			}
			marked, err := e.MarkBlockActionsUnverified([]string{"act_unknown"})
			if marked != 1 || !errors.Is(err, cause) || !errors.Is(err, ErrBlockBatchState) || !errors.Is(e.blockBatchStateErr, cause) || !e.unverifiedBlockActions["act_unknown"] {
				t.Fatalf("Mark = %d, %v; hold = %v, remembered = %v", marked, err, e.blockBatchStateErr, e.unverifiedBlockActions)
			}
			e.clearStateCacheLocked()
			if e.IsBlocked("203.0.113.11") || e.BlockedCount() != 0 || e.RuleCounts().Blocked != 0 || e.Status()["blocked"] != 0 {
				t.Fatal("a failed marking write reported the unresolved row after reload")
			}
			e.mu.Lock()
			initial := e.computeInitialBlockStateLocked()
			e.mu.Unlock()
			if len(initial.blocked4) != 0 || len(initial.blocked6) != 0 {
				t.Fatal("a failed marking write seeded the unresolved row after reload")
			}
			writeFirewallStateJSON = prev
			wantMarked := 1
			if afterRename {
				wantMarked = 0
			}
			if marked, err := e.MarkBlockActionsUnverified([]string{"act_unknown"}); err != nil || marked != wantMarked || e.blockBatchStateErr != nil || len(e.unverifiedBlockActions) != 0 {
				t.Fatalf("retry = %d, %v; hold = %v, remembered = %v", marked, err, e.blockBatchStateErr, e.unverifiedBlockActions)
			}
			state := e.loadStateFile()
			upsertBlockedEntryInState(&state, BlockedEntry{IP: "203.0.113.13", Reason: "operator"})
			if err := e.saveState(&state); err != nil {
				t.Fatal(err)
			}
			e.clearStateCacheLocked()
			if e.IsBlocked("203.0.113.11") || !e.IsBlocked("203.0.113.13") || e.BlockedCount() != 1 {
				t.Fatal("successful persistence lost the unverified row or the new operator row")
			}
		})
	}
}

func TestMarkUnverifiedRefusesUnreadableRawState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &Engine{statePath: dir, cfg: &FirewallConfig{}}
	for _, ids := range [][]string{nil, {""}} {
		if marked, err := e.MarkBlockActionsUnverified(ids); err != nil || marked != 0 || e.blockBatchStateErr != nil {
			t.Fatalf("empty marking = %d, %v; hold = %v", marked, err, e.blockBatchStateErr)
		}
	}
	if marked, err := e.MarkBlockActionsUnverified([]string{"act_unknown"}); err == nil || marked != 0 || e.blockBatchStateErr == nil {
		t.Fatalf("Mark = %d, %v; hold = %v", marked, err, e.blockBatchStateErr)
	}
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil || string(data) != "{" {
		t.Fatalf("unreadable state was changed: %q, %v", data, err)
	}
}

func TestUnverifiedRowsAreExcludedFromDurableSetPlanning(t *testing.T) {
	at := time.Now()
	state := unverifiedRowsState(at)
	sets := desiredActionSets(state, true, at)
	if len(sets["blocked_ips"]) != 2 || len(sets["blocked_ips6"]) != 0 {
		t.Fatalf("desired sets = %+v; want only the two proven IPv4 rows", sets)
	}
	for _, elem := range sets["blocked_ips"] {
		ip := net.IP(elem.Key).String()
		if ip != "203.0.113.10" && ip != "203.0.113.12" {
			t.Fatalf("durable planning restores %s", ip)
		}
	}
	if len(state.Blocked) != 4 || !state.Blocked[1].Unverified || !state.Blocked[2].Unverified {
		t.Fatalf("durable planning changed the stored rows: %+v", state.Blocked)
	}
}

func TestFailedActionRowsStaySuppressedUntilSafePersistence(t *testing.T) {
	at := time.Now()
	dir := t.TempDir()
	writeEngineStateFile(t, dir, FirewallState{Blocked: []BlockedEntry{
		{IP: "203.0.113.11", ActionID: "act_failed", ExpiresAt: at.Add(time.Hour)},
		{IP: "203.0.113.12", Reason: "operator"},
	}})
	e := &Engine{statePath: dir, cfg: &FirewallConfig{IPv6: true}, expiryClock: func() time.Time { return at }}
	if !e.IsBlocked("203.0.113.11") {
		t.Fatal("fixture did not warm the failed row into the cache")
	}
	e.mu.Lock()
	e.suppressFailedBlockActionsLocked([]string{"act_failed", ""})
	e.blockBatchStateErr = errors.Join(ErrBlockBatchState, errors.New("state restore refused"))
	e.mu.Unlock()
	if e.IsBlocked("203.0.113.11") || !e.IsBlocked("203.0.113.12") || e.BlockedCount() != 1 || e.Status()["blocked"] != 1 {
		t.Fatal("failed-row suppression changed the wrong cache rows")
	}
	raw, ok := e.loadStateFileRawLocked()
	failed, present := blockedStateEntry(raw, "203.0.113.11")
	if !ok || !present || failed.Unverified {
		t.Fatalf("failed rows must stay raw and unmarked until persistence: %+v, %t, %t", failed, ok, present)
	}
	e.clearStateCacheLocked()
	if e.IsBlocked("203.0.113.11") || e.RuleCounts().Blocked != 1 {
		t.Fatal("a cache reload restored a proven failed row")
	}
	e.mu.Lock()
	initial := e.computeInitialBlockStateLocked()
	e.mu.Unlock()
	if len(initial.blocked4) != 1 || net.IP(initial.blocked4[0].Key).String() != "203.0.113.12" || len(initial.blocked6) != 0 {
		t.Fatalf("failed-row seeding = %+v", initial)
	}
	if err := e.saveState(&raw); err != nil {
		t.Fatal(err)
	}
	if len(e.failedBlockActions) != 0 || e.blockBatchStateErr != nil {
		t.Fatalf("safe persistence retained failed IDs %v or hold %v", e.failedBlockActions, e.blockBatchStateErr)
	}
	e.clearStateCacheLocked()
	stored, ok := e.loadStateFileRawLocked()
	if !ok || len(stored.Blocked) != 1 || stored.Blocked[0].IP != "203.0.113.12" || e.IsBlocked("203.0.113.11") {
		t.Fatalf("safe persistence kept the failed row: %+v, readable = %t", stored.Blocked, ok)
	}
}

func TestBlockedEntryActionFieldsParticipateInSnapshotEquality(t *testing.T) {
	at := time.Now()
	base := BlockedEntry{IP: "203.0.113.11", ActionID: "act_one", BlockedAt: at, ExpiresAt: at.Add(time.Hour)}
	changed := base
	changed.ActionID = "act_two"
	if SameBlockedEntry(base, changed) {
		t.Fatal("different attempts compare equal for undo")
	}
	changed = base
	changed.Unverified = true
	if SameBlockedEntry(base, changed) {
		t.Fatal("an unverified row compares equal to its prior verified snapshot")
	}
	changed = base
	changed.BlockedAt = base.BlockedAt.In(time.FixedZone("offset", 3600))
	changed.ExpiresAt = base.ExpiresAt.In(time.FixedZone("offset", 3600))
	if !SameBlockedEntry(base, changed) {
		t.Fatal("equal timestamps at different offsets no longer compare equal")
	}
}

// An unverified row is never an automatic victim (spec 5.4) and never
// occupies a counted slot in the state fallback, even after its expiry.
func TestLegacyEvictionSkipsUnverifiedRows(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	state := FirewallState{Blocked: []BlockedEntry{
		{IP: "192.0.2.10", ExpiresAt: at.Add(-time.Hour), ActionID: "act_unknown", Unverified: true},
		{IP: "192.0.2.11", ExpiresAt: at.Add(time.Minute), ActionID: "act_pending", Unverified: true},
		{IP: "203.0.113.40", ExpiresAt: at.Add(2 * time.Hour)},
		{IP: "203.0.113.41", ExpiresAt: at.Add(time.Hour)},
		{IP: "203.0.113.42"},
	}}
	if victim, ok := soonestExpiringTempIP(state, ""); !ok || victim != "203.0.113.41" {
		t.Fatalf("victim = %q, %t; want the soonest verified temporary row", victim, ok)
	}
	if perm, temp := blockedStatePermTempCounts(state, ""); perm != 1 || temp != 2 {
		t.Fatalf("fallback counts = %d permanent, %d temporary; want 1 and 2", perm, temp)
	}
}
