//go:build linux

package firewall

import (
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/actionlog"
)

// A durable single-target block that evicts at the temporary limit records
// the row it removes as its victim, exactly as committed state held it.
func TestDurableEvictionRecordsItsVictim(t *testing.T) {
	// A caller without an ID gets one when the plan is admitted; the
	// manifest's member must carry the same one.
	for _, id := range []string{"evicting", ""} {
		now := time.Now().Round(0)
		later := BlockedEntry{IP: "203.0.113.50", Reason: "later", Source: "scan", BlockedAt: now.Add(-time.Hour), ExpiresAt: now.Add(2 * time.Hour)}
		soonest := BlockedEntry{IP: "203.0.113.51", Reason: "soonest", Source: "scan", BlockedAt: now.Add(-time.Hour), ExpiresAt: now.Add(10 * time.Minute)}
		e, s := batchPlanEngine(t, FirewallConfig{DenyTempIPLimit: 2}, FirewallState{Blocked: []BlockedEntry{later, soonest}})
		req := ActionRequest{ID: id, Target: "203.0.113.52", Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour}
		if _, err := e.BlockIPRequest(req, nil); !errors.Is(err, errBatchPlanStop) {
			t.Fatalf("block %q = %v, want the captured plan", id, err)
		}
		if len(s.admitted) != 1 {
			t.Fatalf("block %q admitted %d plans", id, len(s.admitted))
		}
		plan := s.admitted[0]
		if plan.Request.ID == "" || len(plan.Members) != 1 || plan.Members[0].Request != plan.Request || plan.Members[0].Budget != plan.Budget {
			t.Fatalf("block %q manifest = %#v, header %#v", id, plan.Members, plan.Request)
		}
		if !reflect.DeepEqual(plan.Members[0].Victims, []BlockedEntry{soonest}) {
			t.Fatalf("block %q victims = %#v, want the soonest-expiring row", id, plan.Members[0].Victims)
		}
		for _, row := range plan.After.Blocked {
			if row.IP == soonest.IP {
				t.Fatalf("block %q kept its victim: %#v", id, plan.After.Blocked)
			}
		}
	}
}

// A block that evicts nothing keeps the record every earlier build writes.
func TestDurableBlockWithoutEvictionHasNoManifest(t *testing.T) {
	e, s := batchPlanEngine(t, FirewallConfig{DenyTempIPLimit: 2}, FirewallState{})
	req := ActionRequest{ID: "plain", Target: "203.0.113.52", Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour}
	if _, err := e.BlockIPRequest(req, nil); !errors.Is(err, errBatchPlanStop) || len(s.admitted) != 1 {
		t.Fatalf("block = %v, admitted %d", err, len(s.admitted))
	}
	if s.admitted[0].Members != nil {
		t.Fatalf("plain block carries a manifest: %#v", s.admitted[0].Members)
	}
}

// A row the store cannot record as a victim, one spelled other than its
// canonical address, is passed over for the next soonest-expiring row.
func TestDurableEvictionSkipsVictimsItCannotRecord(t *testing.T) {
	now := time.Now().Round(0)
	mapped := BlockedEntry{IP: "::ffff:203.0.113.53", Reason: "legacy spelling", Source: "scan", BlockedAt: now.Add(-time.Hour), ExpiresAt: now.Add(5 * time.Minute)}
	later := BlockedEntry{IP: "203.0.113.50", Reason: "later", Source: "scan", BlockedAt: now.Add(-time.Hour), ExpiresAt: now.Add(2 * time.Hour)}
	e, s := batchPlanEngine(t, FirewallConfig{DenyTempIPLimit: 2}, FirewallState{Blocked: []BlockedEntry{mapped, later}})
	req := ActionRequest{ID: "evicting", Target: "203.0.113.52", Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour}
	if _, err := e.BlockIPRequest(req, nil); !errors.Is(err, errBatchPlanStop) || len(s.admitted) != 1 {
		t.Fatalf("block = %v, admitted %d", err, len(s.admitted))
	}
	if members := s.admitted[0].Members; len(members) != 1 || !reflect.DeepEqual(members[0].Victims, []BlockedEntry{later}) {
		t.Fatalf("manifest = %#v, want the canonical row as victim", members)
	}
}

// Each removed victim gets an evict_temp record beside its member's record,
// in the same durable write, carrying the member's identity and outcome.
func TestFirewallAuditRecordsEachRemovedVictim(t *testing.T) {
	sink := captureFirewallAudit(t)
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	victim := BlockedEntry{IP: "203.0.113.90", Reason: "earlier", Source: "scan", BlockedAt: at.Add(-time.Hour), ExpiresAt: at.Add(30 * time.Minute)}
	req := ActionRequest{ID: "evicting", Operation: "block", Target: "203.0.113.10", Reason: "brute force", Actor: "auto", Source: "scan", Automatic: true, TTL: time.Hour, FindingID: "finding-one"}
	a := FirewallAction{
		Request: req, Members: []ActionMember{{Request: req, Victims: []BlockedEntry{victim}}},
		Before: FirewallState{Blocked: []BlockedEntry{victim}},
		After:  FirewallState{Blocked: []BlockedEntry{{IP: req.Target, Reason: req.Reason, BlockedAt: at, ExpiresAt: at.Add(time.Hour)}}},
		Phase:  "verified", AuditVersion: 3, UpdatedAt: at.Add(time.Minute),
	}
	if err := writeFirewallActionAudit(a); err != nil {
		t.Fatal(err)
	}
	if len(sink.single) != 0 || len(sink.batch) != 1 || len(sink.batch[0]) != 2 {
		t.Fatalf("audit = single %#v, batch %#v; want one durable write of block and eviction", sink.single, sink.batch)
	}
	block, evict := sink.batch[0][0], sink.batch[0][1]
	if block.Action != "block" || block.Target != req.Target {
		t.Fatalf("block record = %#v", block)
	}
	if evict.Action != "evict_temp" || evict.Target != victim.IP || evict.Reason != "temp deny limit reached; evicted soonest-expiring entry" || evict.ActionID != req.ID || evict.ActionVersion != 3 ||
		evict.FindingID != req.FindingID || evict.Op != "respond.block_ip" || evict.Result != actionlog.Result("verified") || !evict.Timestamp.Equal(a.UpdatedAt) {
		t.Fatalf("eviction record = %#v", evict)
	}
	alias := victim
	alias.IP = "::ffff:203.0.113.90"
	for _, row := range []BlockedEntry{victim, alias} {
		sink.single, sink.batch = nil, nil
		kept := a
		kept.After.Blocked = append(slices.Clone(kept.After.Blocked), row)
		if err := writeFirewallActionAudit(kept); err != nil {
			t.Fatal(err)
		}
		if len(sink.batch) != 0 || len(sink.single) != 1 || sink.single[0].Action != "block" {
			t.Fatalf("a victim kept as %s was audited as evicted: single %#v, batch %#v", row.IP, sink.single, sink.batch)
		}
	}
}

// A retry of a stored batch returns the stored action even while dry run
// is on: dry run refuses only new work.
func TestBlockBatchReplaysUnderDryRun(t *testing.T) {
	a, b := batchMember("member-a", "203.0.113.20"), batchMember("member-b", "203.0.113.21")
	stored := FirewallAction{Request: batchHeader(), Members: []ActionMember{{Request: a}, {Request: b}}, Phase: "verified", AuditVersion: 2, AuditAck: 2}
	e, s := batchPlanEngine(t, FirewallConfig{}, FirewallState{})
	s.stored[stored.Request.ID] = stored
	e.SetDryRunEnabledFunc(func() bool { return true })
	result, err := e.BlockBatchRequest(batchHeader(), []ActionRequest{a, b}, nil)
	if err != nil || result.Action.Request != stored.Request || len(s.admitted) != 0 {
		t.Fatalf("dry-run replay = %#v, %v; admitted %d", result.Action.Request, err, len(s.admitted))
	}
	single := FirewallAction{Request: a, Phase: "verified", AuditVersion: 2, AuditAck: 2}
	e, s = batchPlanEngine(t, FirewallConfig{}, FirewallState{})
	s.stored[a.ID] = single
	e.SetDryRunEnabledFunc(func() bool { return true })
	if result, err = e.BlockBatchRequest(batchHeader(), []ActionRequest{a, b}, nil); err != nil || result.Action.Request != a || len(s.admitted) != 0 {
		t.Fatalf("dry-run singleton replay = %#v, %v; admitted %d", result.Action.Request, err, len(s.admitted))
	}
}
