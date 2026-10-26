//go:build linux

package firewall

import (
	"encoding/json"
	"errors"
	"io"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

// One count decision uses one family dump each, including target exclusion.
// A count-only test seam cannot supply address ownership.
func TestOperatorOccupancyDecisionUsesOneImage(t *testing.T) {
	for _, mode := range []string{"dump", "counts only"} {
		t.Run(mode, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			f.e.cfg.DenyTempIPLimit = 1
			state := FirewallState{Blocked: []BlockedEntry{
				{IP: "203.0.113.90", ActionID: "act_owned", ExpiresAt: f.at.Add(time.Hour)},
				{IP: "203.0.113.91", ExpiresAt: f.at.Add(2 * time.Hour)},
			}}
			f.live["203.0.113.90"], f.live["203.0.113.91"] = time.Hour, 2*time.Hour
			counts, dumps := 0, 0
			f.e.liveBlockCounts = func() (int, int, error) { counts++; return 0, 0, nil }
			dump := f.e.liveBlockedDump
			f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) { dumps++; return dump(set) }
			wantDumps := 2
			if mode == "counts only" {
				f.e.liveBlockedDump, f.e.conn = nil, nil
				wantDumps = 0
			}
			f.e.mu.Lock()
			_, _, _, victim, err := f.e.blockIPTargetFromStates("203.0.113.92", time.Hour, false, state, state)
			f.e.mu.Unlock()
			if err != nil || victim != "203.0.113.91" || dumps != wantDumps || counts != 0 {
				t.Fatalf("decision: victim=%q err=%v dumps=%d counts=%d", victim, err, dumps, counts)
			}
		})
	}
}

func TestOperatorOccupancyDumpBoundaries(t *testing.T) {
	for _, mode := range []string{"second dump fails", "IPv6 disabled", "alias exclusion", "alias fallback", "expires during dump"} {
		t.Run(mode, func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			state := FirewallState{Blocked: []BlockedEntry{
				{IP: "203.0.113.90", ActionID: "act_owned", ExpiresAt: f.at.Add(time.Hour)},
				{IP: "203.0.113.91", ExpiresAt: f.at.Add(3 * time.Hour)},
				{IP: "2001:db8::91", ExpiresAt: f.at.Add(3 * time.Hour)},
			}}
			f.live["203.0.113.90"], f.live["203.0.113.91"], f.live["2001:db8::91"] = time.Hour, 3*time.Hour, 3*time.Hour
			want, wantDumps, exclude := 2, 2, ""
			if mode == "IPv6 disabled" {
				f.e.cfg.IPv6, f.e.setBlocked6 = false, nil
				want, wantDumps = 1, 1
			}
			if mode == "alias exclusion" || mode == "alias fallback" {
				exclude, want = "::ffff:203.0.113.91", 1
			}
			if mode == "expires during dump" {
				want = 3
				state.Blocked[0].Unverified = true
			}
			dump, dumps := f.e.liveBlockedDump, 0
			f.e.liveBlockedDump = func(set *nftables.Set) ([]nftables.SetElement, error) {
				dumps++
				if mode == "second dump fails" && dumps == 2 {
					return nil, errors.New("second family unavailable")
				}
				if mode == "expires during dump" {
					f.e.leaseClock = func() (time.Time, time.Time) { return f.at.Add(2 * time.Hour), f.at.Add(2 * time.Hour) }
				}
				return dump(set)
			}
			if mode == "alias fallback" {
				f.e.liveBlockedDump, f.e.conn, wantDumps = nil, nil, 0
			}
			f.e.mu.Lock()
			got := f.e.operatorTempCountLocked(state, exclude)
			f.e.mu.Unlock()
			if got != want || dumps != wantDumps {
				t.Fatalf("count=%d dumps=%d, want %d/%d", got, dumps, want, wantDumps)
			}
		})
	}
}

// Shared sockets have no reply deadline. The existing transient connection
// installs the bound; its socket deadline behavior has separate transport tests.
func TestOperatorOccupancyUsesFreshSockets(t *testing.T) {
	f := newBatchFixture(t, FirewallState{})
	shared, fresh := 0, 0
	conn, err := nftables.New(nftables.AsLasting(), nftables.WithTestDial(func([]netlink.Message) ([]netlink.Message, error) {
		shared++
		return nil, errors.New("shared socket read")
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseLasting() })
	conn.TestDial = func([]netlink.Message) ([]netlink.Message, error) { fresh++; return nil, io.EOF }
	f.e.conn, f.e.liveBlockedDump = conn, nil
	state := FirewallState{Blocked: []BlockedEntry{{IP: "203.0.113.90", ExpiresAt: f.at.Add(time.Hour)}}}
	f.e.mu.Lock()
	got := f.e.operatorTempCountLocked(state, "")
	f.e.mu.Unlock()
	if got != 0 || shared != 0 || fresh != 2 {
		t.Fatalf("count=%d shared=%d fresh=%d", got, shared, fresh)
	}
}

// A temporary automatic stamp is not retained by permanent promotion.
func TestLegacyStampPromotion(t *testing.T) {
	conn, _ := nftConnCapturingRules(t)
	e := newBlockedSetWireTestEngine(t, conn)
	row := BlockedEntry{IP: "203.0.113.90", Automatic: true, ExpiresAt: time.Now().Add(time.Hour)}
	writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{row}})
	if err := e.PromoteToPermanentBlock(row.IP, "auto-block: copied"); err != nil {
		t.Fatal(err)
	}
	got, ok := blockedStateEntry(readRawFirewallState(t, e), row.IP)
	if !ok || got.Automatic || !got.ExpiresAt.IsZero() {
		t.Fatalf("promotion: %+v", got)
	}
}

func TestLegacyStampRecoveryPaths(t *testing.T) {
	t.Run("failed operator replacement", func(t *testing.T) {
		conn, _ := nftConnReturningErrsThenOK(t, syscall.EPERM)
		e := newBlockedSetWireTestEngine(t, conn)
		row := BlockedEntry{IP: "203.0.113.90", Automatic: true, ExpiresAt: time.Now().Add(time.Hour)}
		writeRawFirewallState(t, e, FirewallState{Blocked: []BlockedEntry{row}})
		if err := e.BlockIPForce(row.IP, "operator", 2*time.Hour); err == nil {
			t.Fatal("kernel rejection accepted")
		}
		got, ok := blockedStateEntry(readRawFirewallState(t, e), row.IP)
		if !ok || !got.Automatic || !got.ExpiresAt.Equal(row.ExpiresAt) {
			t.Fatalf("failed replacement lost prior state: %+v", got)
		}
	})
	t.Run("durable replay", func(t *testing.T) {
		e, store := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
		a, b := batchMember("member-a", "203.0.113.90"), batchMember("member-b", "203.0.113.91")
		row := BlockedEntry{IP: a.Target, ActionID: a.ID, Automatic: true, ExpiresAt: time.Now().Add(time.Hour)}
		saved := FirewallAction{Request: batchHeader(), Members: []ActionMember{{Request: a}, {Request: b}}, Phase: "verified", AuditVersion: 2, AuditAck: 2, Before: FirewallState{Blocked: []BlockedEntry{row}}, After: FirewallState{Blocked: []BlockedEntry{row}}}
		raw, err := json.Marshal(saved)
		if err != nil {
			t.Fatal(err)
		}
		var loaded FirewallAction
		if err = json.Unmarshal(raw, &loaded); err != nil {
			t.Fatal(err)
		}
		store.stored[saved.Request.ID] = loaded
		result, err := e.BlockBatchRequest(batchHeader(), []ActionRequest{a, b}, nil)
		if err != nil || len(store.admitted) != 0 || len(result.Action.Before.Blocked) != 1 || len(result.Action.After.Blocked) != 1 || !result.Action.Before.Blocked[0].Automatic || !result.Action.After.Blocked[0].Automatic {
			t.Fatalf("replay lost provenance: %+v %v", result, err)
		}
	})
}
