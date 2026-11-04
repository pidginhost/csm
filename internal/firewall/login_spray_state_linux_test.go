//go:build linux

package firewall

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestUndoPreservesLoginSprayEviction(t *testing.T) {
	conn, _ := nftConnReturningErrsThenOK(t)
	e := newBlockedSetWireTestEngine(t, conn)
	at := e.expiryClock()
	spray := sprayRow("192.0.2.120", at, 24*time.Hour)
	other := automaticRow("198.51.100.120", "other block", at, time.Hour)
	writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{spray, other}})
	before, after, err := e.BlockIPForUndo(spray.IP, "operator block", 0)
	if err != nil {
		t.Fatal(err)
	}
	if after.LoginSpray {
		t.Fatal("operator replacement inherited the spray tag")
	}
	if err := e.RestoreBlockIfUnchanged(spray.IP, after, before); err != nil {
		t.Fatal(err)
	}
	state := readRawFirewallState(t, e)
	restored, ok := blockedStateEntry(state, spray.IP)
	if !ok || !restored.LoginSpray || !restored.Automatic || !restored.ExpiresAt.Equal(spray.ExpiresAt) {
		t.Fatalf("undo lost the spray identity or renewed its lifetime: %+v", restored)
	}
	e.mu.Lock()
	victim, found := e.evictionVictimLocked(state, "", true)
	e.mu.Unlock()
	if !found || victim != spray.IP {
		t.Fatalf("undo changed the preferred victim: %q, %t", victim, found)
	}
}

func TestLoginSprayDurableReplayIdentity(t *testing.T) {
	at := time.Now().UTC()
	req := normalizeActionRequest(ActionRequest{ID: "spray-request", Operation: "block", Target: "192.0.2.121", Automatic: true, TTL: time.Hour, LoginSpray: true})
	row := sprayRow(req.Target, at, time.Hour)
	original := FirewallAction{Request: req, After: FirewallState{Blocked: []BlockedEntry{row}}, Phase: "verified"}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var saved FirewallAction
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if !saved.IsRequest(req) || !SameBlockedEntry(saved.After.Blocked[0], row) {
		t.Fatal("persisted action lost its spray identity")
	}
	e := &Engine{lifecycle: &Lifecycle{Store: replayLifecycleStore{action: saved, current: saved.After}}}
	changed := req
	changed.LoginSpray = false
	if _, err := e.BlockIPRequest(changed, nil); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("changed spray identity replayed: %v", err)
	}
	if outcome, err := e.BlockIPRequest(req, nil); err != nil || outcome != BlockOutcomeNoop {
		t.Fatalf("original request replay = %s, %v", outcome, err)
	}
	if e.stateCache == nil || len(e.stateCache.Blocked) != 1 || !e.stateCache.Blocked[0].LoginSpray {
		t.Fatal("replay lost the committed spray tag")
	}
	var old BlockedEntry
	if err := json.Unmarshal([]byte(`{"ip":"192.0.2.122"}`), &old); err != nil || old.LoginSpray {
		t.Fatalf("old row gained a spray tag: %+v, %v", old, err)
	}
}

func TestBlockedEntriesPreserveLoginSpray(t *testing.T) {
	at := time.Now().UTC()
	row := sprayRow("192.0.2.123", at, time.Hour)
	expired := sprayRow("192.0.2.125", at, -time.Hour)
	unproven := sprayRow("192.0.2.126", at, time.Hour)
	unproven.Unverified = true
	state := FirewallState{Blocked: []BlockedEntry{row, expired, unproven}}
	for _, durable := range []bool{false, true} {
		e := &Engine{statePath: t.TempDir(), cfg: &FirewallConfig{}}
		if durable {
			e.lifecycle = &Lifecycle{Store: replayLifecycleStore{current: state}}
		} else {
			writeRawFirewallState(t, e, state)
		}
		lister, ok := any(e).(interface {
			BlockedEntries() ([]BlockedEntry, error)
		})
		if !ok {
			t.Fatal("engine cannot supply authoritative block tags")
		}
		rows, err := lister.BlockedEntries()
		if err != nil || len(rows) != 1 || !SameBlockedEntry(rows[0], row) {
			t.Fatalf("durable=%t: rows=%+v, err=%v", durable, rows, err)
		}
		rows[0].LoginSpray = false
		again, err := lister.BlockedEntries()
		if err != nil || len(again) != 1 || !again[0].LoginSpray {
			t.Fatal("caller modified the engine's spray tag")
		}
	}
}

type unreadableSprayStore struct {
	ActionStore
	err error
}

func (s unreadableSprayStore) ReadFirewallState() (FirewallState, uint64, error) {
	return FirewallState{}, 0, s.err
}

func TestBlockedEntriesRejectStaleCacheOnReadError(t *testing.T) {
	cause := errors.New("committed state unavailable")
	e := &Engine{
		lifecycle:  &Lifecycle{Store: unreadableSprayStore{err: cause}},
		stateCache: &FirewallState{Blocked: []BlockedEntry{sprayRow("192.0.2.127", time.Now(), time.Hour)}},
	}
	if rows, err := e.BlockedEntries(); len(rows) != 0 || !errors.Is(err, cause) {
		t.Fatalf("unreadable provenance returned cached tags: %+v, %v", rows, err)
	}
}

func TestLoginSprayBatchRowsKeepTag(t *testing.T) {
	for _, count := range []int{1, 2} {
		e, store := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
		spray := batchMember("spray-member", "192.0.2.124")
		spray.LoginSpray = true
		members := []ActionRequest{spray, batchMember("other-member", "198.51.100.124")}[:count]
		if _, err := e.BlockBatchRequest(batchHeader(), members, nil); !errors.Is(err, errBatchPlanStop) {
			t.Fatalf("planning failed: %v", err)
		}
		if len(store.admitted) != 1 || len(store.admitted[0].After.Blocked) != count {
			t.Fatalf("wrong batch plan: %+v", store.admitted)
		}
		for i, row := range store.admitted[0].After.Blocked {
			if row.LoginSpray != members[i].LoginSpray || !row.Automatic || row.ExpiresAt.IsZero() {
				t.Fatalf("batch row lost its request's tag: %+v", row)
			}
		}
	}
}
