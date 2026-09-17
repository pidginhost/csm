package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

type cleanupQueueUnreadable struct {
	OS
	path string
}

func TestAutoBlockCleanupUnknownReadRebindsCompletedGeneration(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	const ip = "192.0.2.193"
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	store.SetGlobal(db)
	if err = writeBlockState(cfg.StatePath, &blockState{IPs: []blockedIP{{IP: ip, BlockedAt: time.Now().Add(-time.Minute)}}}); err != nil {
		t.Fatal(err)
	}
	writeFirewallFlushState(t, cfg.StatePath)
	restore := failRetryWrite(t, cfg.StatePath)
	if err = flushAutoBlockStateForTest(t, cfg.StatePath); err == nil {
		t.Fatal("old completed cleanup did not retain its tracker source")
	}
	restore()
	result, err := ApplyBlock(cfg, ApplyBlockRequest{IP: ip, Reason: "new generation before unknown cleanup", TTL: time.Hour, Source: BlockSourceCentral})
	if err != nil || result.Outcome != firewall.BlockOutcomeLive {
		t.Fatalf("new block missing: result=%+v err=%v", result, err)
	}
	if _, found := db.GetPermanentBlock(ip); !found {
		t.Fatal("actual new store row missing")
	}
	writeFirewallFlushState(t, cfg.StatePath, ip)
	oldOS := osFS
	defer func() { osFS = oldOS }()
	osFS = cleanupQueueUnreadable{OS: realOS{}, path: filepath.Join(cfg.StatePath, blockStateFile)}
	flushed, err := FlushAutoBlockState(cfg.StatePath, func() error { writeFirewallFlushState(t, cfg.StatePath); return nil })
	if err == nil || !flushed.Flushed {
		t.Fatalf("unknown tracker cleanup path missing: result=%+v err=%v", flushed, err)
	}
	if _, found := db.GetPermanentBlock(ip); found {
		t.Fatal("known engine admission did not complete actual new cleanup")
	}
	osFS = oldOS
	if err = InitAutoBlockQueueHealth(cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	row := cleanupQueueRow(t, time.Now())
	if row.Depth != 1 || row.DepthUnavailable || row.DroppedTotal != 0 || !row.DroppedLowerBound {
		t.Fatalf("read recovery did not rebind retained cleanup: %+v", row)
	}
	AutoBlockIPs(cfg, nil)
	row = cleanupQueueRow(t, time.Now())
	if row.Depth != 0 || row.InFlight != 0 || row.DroppedTotal != 0 || !row.DroppedLowerBound {
		t.Fatalf("baseline older than actual unknown-read cleanup invented a fresh loss: %+v", row)
	}
}

func (f cleanupQueueUnreadable) ReadFile(path string) ([]byte, error) {
	if path == f.path {
		return nil, os.ErrPermission
	}
	return f.OS.ReadFile(path)
}

// The old block is actually cleaned, then its acknowledgment is forgotten by
// another unreadable batch. Rediscovery must stay conservative. After a known
// baseline, an actual new ApplyBlock must own its own later cleanup loss.
func TestAutoBlockCleanupFreshGenerationAfterUnknownHistory(t *testing.T) {
	for _, baselineMode := range []string{"flush", "startup"} {
		for _, fresh := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/fresh=%v", baselineMode, fresh), func(t *testing.T) {
				cfg := autoBlockQueueFixture(t, func() error { return nil })
				const ip = "192.0.2.190"
				storeDir := t.TempDir()
				db, err := store.Open(storeDir)
				if err != nil {
					t.Fatal(err)
				}
				store.SetGlobal(db)
				t.Cleanup(func() { _ = db.Close() })
				if err = db.AddTempBlock(ip, "old cleanup evidence", time.Now().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
				initial := &blockState{IPs: []blockedIP{{IP: ip, BlockedAt: time.Now().Add(-time.Minute)}}}
				if baselineMode == "startup" {
					initial.CleanupPending = []string{ip}
				}
				if err = writeBlockState(cfg.StatePath, initial); err != nil {
					t.Fatal(err)
				}
				writeFirewallFlushState(t, cfg.StatePath)
				failFlush := func(n int) {
					t.Helper()
					restore := failRetryWrite(t, cfg.StatePath)
					if flushErr := flushAutoBlockStateForTest(t, cfg.StatePath); flushErr == nil {
						t.Fatal("real stale-temp write unexpectedly succeeded")
					}
					restore()
					saved := filepath.Join(cfg.StatePath, blockStateFile+".tmp.saved")
					if renameErr := os.Rename(saved, fmt.Sprintf("%s.%d", saved, n)); renameErr != nil {
						t.Fatal(renameErr)
					}
				}
				failFlush(1)
				if _, found := db.GetPermanentBlock(ip); found {
					t.Fatal("old cleanup did not remove the real store row")
				}
				first := cleanupQueueRow(t, time.Now())
				if first.Depth != 1 || first.DroppedTotal != 0 {
					t.Fatalf("old acknowledged retry changed: %+v", first)
				}

				oldOS := osFS
				t.Cleanup(func() { osFS = oldOS })
				osFS = cleanupQueueUnreadable{OS: realOS{}, path: filepath.Join(cfg.StatePath, blockStateFile)}
				writeFirewallFlushState(t, cfg.StatePath, "192.0.2.191")
				result, err := FlushAutoBlockState(cfg.StatePath, func() error { writeFirewallFlushState(t, cfg.StatePath); return nil })
				if err == nil || !result.Flushed {
					t.Fatalf("unknown successful flush missing: result=%+v err=%v", result, err)
				}
				osFS = oldOS
				unknown := cleanupQueueRow(t, time.Now())
				if !unknown.DepthUnavailable || !unknown.DroppedLowerBound || unknown.DroppedTotal != 0 {
					t.Fatalf("unknown outcome fabricated loss: %+v", unknown)
				}
				// Startup observation or a failed retry establishes the old source
				// baseline without creating a new block or clearing unknown history.
				if err = db.Close(); err != nil {
					t.Fatal(err)
				}
				if baselineMode == "startup" {
					if err = InitAutoBlockQueueHealth(cfg.StatePath); err != nil {
						t.Fatal(err)
					}
					// Keep the old block as the retry source after removing its redundant marker.
					initial.CleanupPending = nil
					if err = writeBlockState(cfg.StatePath, initial); err != nil {
						t.Fatal(err)
					}
				} else {
					failFlush(2)
				}
				baseline := cleanupQueueRow(t, time.Now())
				if baseline.Depth != 1 || baseline.DepthUnavailable || baseline.DroppedTotal != 0 {
					t.Fatalf("rediscovered old retry changed: %+v", baseline)
				}
				db, err = store.Open(storeDir)
				if err != nil {
					t.Fatal(err)
				}
				store.SetGlobal(db)
				if fresh {
					blockResult, blockErr := ApplyBlock(cfg, ApplyBlockRequest{IP: ip, Reason: "known fresh block", TTL: time.Hour, Source: BlockSourceCentral})
					if blockErr != nil || blockResult.Outcome != firewall.BlockOutcomeLive || len(blockResult.Findings) != 1 {
						t.Fatalf("actual fresh block missing: result=%+v err=%v", blockResult, blockErr)
					}
					if _, found := db.GetPermanentBlock(ip); !found {
						t.Fatal("fresh block did not persist its actual store row")
					}
					state, readErr := readBlockState(cfg.StatePath)
					if readErr != nil || len(state.IPs) != 2 || !state.IPs[1].BlockedAt.After(state.IPs[0].BlockedAt) {
						t.Fatalf("new durable generation missing: state=%+v err=%v", state, readErr)
					}
				}
				if err = db.Close(); err != nil {
					t.Fatal(err)
				}
				failFlush(3)
				retained := cleanupQueueRow(t, time.Now())
				if retained.Depth != 1 || retained.DroppedTotal != 0 {
					t.Fatalf("failed cleanup was not retained: %+v", retained)
				}
				store.SetGlobal(nil)
				AutoBlockIPs(cfg, nil)
				final := cleanupQueueRow(t, time.Now())
				state, err := readBlockState(cfg.StatePath)
				if err != nil || len(state.IPs) != 0 || len(state.CleanupPending) != 0 {
					t.Fatalf("actual scan did not prune retry sources: state=%+v err=%v", state, err)
				}
				db, err = store.Open(storeDir)
				if err != nil {
					t.Fatal(err)
				}
				_, found := db.GetPermanentBlock(ip)
				if found != fresh {
					t.Fatalf("real leftover store row=%v, want fresh=%v", found, fresh)
				}
				wantLoss := uint64(0)
				if fresh {
					wantLoss = 1
				}
				if final.Depth != 0 || final.InFlight != 0 || final.DroppedTotal != wantLoss || !final.DroppedLowerBound {
					t.Fatalf("generation loss=%d, want %d after confirmed source removal: %+v", final.DroppedTotal, wantLoss, final)
				}
			})
		}
	}
}
