package admissionowner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// An executing owner takes an incident block that carries its root, so the
// legacy block is skipped; a rung that kept no root is refused as policy,
// and legacy still applies it.
func TestExecutingOwnerTakesOnlyRootedDerivedBlocks(t *testing.T) {
	withTestRegistry(t)
	f := newOwnerFixture(t)
	opts := executeOptions(f, newFakeBlocks())
	opts.Caps = func() admission.Caps { return admission.Caps{} }
	opts.Policy = (&policyReader{p: validPolicy(1)}).read
	o := f.start(opts)
	if err := o.do(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	checks.SetResponseAdmission(o)
	t.Cleanup(func() { checks.SetResponseAdmission(nil) })
	blocker := &funnelBlocker{}
	checks.SetIPBlocker(blocker)
	t.Cleanup(func() { checks.SetIPBlocker(nil) })
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	cfg := &config.Config{StatePath: f.statePath}
	cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs, cfg.AutoResponse.BlockExpiry = true, true, "24h"

	root, err := o.Mint(sshFinding(f.host.now(), "offset=1", alert.High))
	if err != nil {
		t.Fatal(err)
	}
	_, err = checks.ApplyBlock(cfg, checks.ApplyBlockRequest{
		IP: targetOf(root), EngineReason: "CSM incident: brute force", Reason: "incident brute force",
		TTL: time.Hour, Source: checks.BlockSourceIncident, Root: root, Entry: admission.EntryIncident,
	})
	if !errors.Is(err, checks.ErrBlockTakenByAdmission) || len(blocker.addresses) != 0 {
		t.Fatalf("rooted incident block: err %v, legacy blocks %v; want it left to the owner", err, blocker.addresses)
	}
	if o.ingress.Len() != 1 {
		t.Fatalf("owner holds %d submissions, want the incident block", o.ingress.Len())
	}
	if _, err = checks.ApplyBlock(cfg, checks.ApplyBlockRequest{
		IP: "198.51.100.70", EngineReason: "CSM incident: brute force", Reason: "incident brute force",
		TTL: time.Hour, Source: checks.BlockSourceIncident, Entry: admission.EntryIncident,
	}); err != nil || len(blocker.addresses) != 1 || blocker.addresses[0] != "198.51.100.70" {
		t.Fatalf("rootless incident block: err %v, legacy blocks %v; want the legacy block", err, blocker.addresses)
	}
	if _, err = checks.ApplyBlock(cfg, checks.ApplyBlockRequest{
		IP: targetOf(root), EngineReason: "CSM incident: permanent", Reason: "incident permanent",
		TTL: 0, Source: checks.BlockSourceIncident, Root: root, Entry: admission.EntryIncident,
	}); err != nil || len(blocker.addresses) != 2 || blocker.addresses[1] != targetOf(root) {
		t.Fatalf("permanent incident block: err %v, legacy blocks %v; want the legacy block", err, blocker.addresses)
	}
	if o.ingress.Len() != 1 {
		t.Fatalf("owner holds %d submissions after legacy rungs, want 1", o.ingress.Len())
	}
}

// Acceptance is final for legacy even when the owner later holds,
// forecasts or loses the request. Prove the later disposition as well as
// the absence of a legacy block; an empty engine alone proves nothing.
func TestTakenBlockNeverFallsBackAfterHandoff(t *testing.T) {
	for _, mode := range []string{"policy_hold", "engine_outage", "dry_run", "displaced"} {
		t.Run(mode, func(t *testing.T) {
			withTestRegistry(t)
			f := newOwnerFixture(t)
			blocks := newFakeBlocks()
			opts := executeOptions(f, blocks)
			var available atomic.Bool
			available.Store(true)
			opts.Blocks = func() BlockEngine {
				if available.Load() {
					return blocks
				}
				return nil
			}
			r := &policyReader{p: validPolicy(1)}
			opts.Policy = r.read
			o := f.start(opts)
			checks.SetResponseAdmission(o)
			t.Cleanup(func() { checks.SetResponseAdmission(nil) })
			legacy := &funnelBlocker{}
			checks.SetIPBlocker(legacy)
			t.Cleanup(func() { checks.SetIPBlocker(nil) })
			t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
			cfg := &config.Config{StatePath: f.statePath}
			cfg.AutoResponse.Enabled, cfg.AutoResponse.BlockIPs = true, true
			root, err := o.Mint(sshFinding(f.host.now(), "offset=1", alert.High))
			if err != nil {
				t.Fatal(err)
			}
			_, err = checks.ApplyBlock(cfg, checks.ApplyBlockRequest{
				IP: targetOf(root), EngineReason: "CSM incident: brute force", Reason: "incident brute force",
				TTL: time.Hour, Source: checks.BlockSourceIncident, Root: root, Entry: admission.EntryIncident,
			})
			if !errors.Is(err, checks.ErrBlockTakenByAdmission) || o.ingress.Len() != 1 || len(legacy.addresses) != 0 {
				t.Fatalf("handoff was not taken: err %v, ingress %d, legacy %v", err, o.ingress.Len(), legacy.addresses)
			}
			if mode == "displaced" {
				for i := 0; i < admission.IngressPositions; i++ {
					finding := sshFinding(f.host.now(), fmt.Sprintf("replacement=%d", i), alert.Critical)
					finding.SourceIP = fmt.Sprintf("198.51.100.%d", i+1)
					e, err := o.Mint(finding)
					if err != nil {
						t.Fatal(err)
					}
					if err := o.Respond(admission.KindBlockIP, targetOf(e), e, admission.EntryIncident); err != nil {
						t.Fatal(err)
					}
				}
				key := admission.CountKey{Event: admission.EventEnded, Reason: admission.ReasonQueueOverflow, Class: admission.ClassC2, Severity: admission.SeverityHigh}
				if n := o.ingress.Stats().Counters.Count(key); n != 1 || o.ingress.Len() != admission.IngressPositions {
					t.Fatalf("accepted block was not displaced: ended %d, ingress %d", n, o.ingress.Len())
				}
			}
			if err := o.do(o.drain); err != nil {
				t.Fatal(err)
			}
			queued := queuedCandidates(t, o)
			if mode == "displaced" {
				if len(queued) != admission.IngressPositions {
					t.Fatalf("displacement retained %d candidates, want %d", len(queued), admission.IngressPositions)
				}
				for _, c := range queued {
					if c.FindingID == root.FindingID() || c.Key.Target.Key() == root.Target().Key() {
						t.Fatal("displaced block survived in the owner queue")
					}
				}
			} else {
				if len(queued) != 1 || queued[0].FindingID != root.FindingID() {
					t.Fatalf("accepted block missing before owner change: %+v", queued)
				}
				p := validPolicy(2)
				switch mode {
				case "policy_hold":
					p.BlockExpiry = 0
				case "engine_outage":
					available.Store(false)
				case "dry_run":
					p.DryRun = true
				}
				r.publish(p)
				turn(t, o)
				id, err := queued[0].ID()
				if err != nil {
					t.Fatal(err)
				}
				c := candidate(t, o, id)
				wantState, wantReason := admission.StateQueued, admission.ReasonEngineUnavailable
				if mode == "dry_run" {
					wantState, wantReason = admission.StateDryRun, 0
				}
				if c.State != wantState || c.Reason != wantReason || c.Attempts != 0 {
					t.Fatalf("accepted block after %s = %+v", mode, c)
				}
				if o.ExecutesBlocks() {
					t.Fatalf("new blocks still go to the owner after %s", mode)
				}
			}
			o.Stop()
			if checked, applied := blocks.calls(); len(checked) != 0 || len(applied) != 0 || len(legacy.addresses) != 0 {
				t.Fatalf("block executed after %s: checks %v, applies %v, legacy %v", mode, checked, applied, legacy.addresses)
			}
			if _, err := os.Stat(filepath.Join(f.statePath, "blocked_ips.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("legacy tracker or retry state appeared after %s: %v", mode, err)
			}
		})
	}
}
