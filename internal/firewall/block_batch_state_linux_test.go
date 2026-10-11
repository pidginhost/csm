//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
)

func TestBlockBatchRequiresReadableState(t *testing.T) {
	for _, warm := range []bool{false, true} {
		for _, apply := range []bool{false, true} {
			t.Run(fmt.Sprintf("warm_%t_apply_%t", warm, apply), func(t *testing.T) {
				f := newBatchFixture(t, FirewallState{Allowed: []AllowedEntry{{IP: "203.0.113.20"}}})
				if warm {
					f.e.mu.Lock()
					_ = f.e.loadStateFile()
					f.e.mu.Unlock()
				}
				path := filepath.Join(f.e.statePath, "state.json")
				broken := []byte(`{"allowed":`)
				if err := os.WriteFile(path, broken, 0o600); err != nil {
					t.Fatal(err)
				}
				writes := f.countWrites(t)
				members := []BlockMember{f.member("act_new", "203.0.113.21")}
				var err error
				if apply {
					var results []BlockResult
					results, err = f.e.ApplyBlockBatch(members)
					if results != nil {
						t.Errorf("unreadable state produced results %+v", results)
					}
				} else {
					var refusals []BlockRefusal
					refusals, err = f.e.CheckBlockBatch(members)
					if refusals != nil {
						t.Errorf("unreadable state produced refusals %q", refusals)
					}
				}
				if !errors.Is(err, ErrBlockBatchState) || *writes != 0 || f.sends != 0 {
					t.Errorf("error %v, writes %d, sends %d; unreadable state must refuse the whole call", err, *writes, f.sends)
				}
				got, readErr := os.ReadFile(path)
				if readErr != nil || !bytes.Equal(got, broken) {
					t.Fatalf("unreadable operator state was overwritten: %q, %v", got, readErr)
				}
			})
		}
	}
}

func TestApplyBlockBatchPreservesExpiryCleanupRows(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			f := newBatchFixture(t, FirewallState{})
			prior := FirewallState{
				Blocked:    []BlockedEntry{{IP: "203.0.113.40", ExpiresAt: f.at.Add(-time.Hour)}},
				BlockedNet: []SubnetEntry{{CIDR: "198.51.100.0/24", ExpiresAt: f.at.Add(-time.Hour)}},
				Allowed:    []AllowedEntry{{IP: "203.0.113.41", ExpiresAt: f.at.Add(-time.Hour)}},
			}
			writeEngineStateFile(t, f.e.statePath, prior)
			if reject {
				f.reply = func(req []netlink.Message) ([]netlink.Message, error) {
					return nltest.Error(int(syscall.EINVAL), req)
				}
			} else {
				f.kernelHolds(map[string]time.Duration{"203.0.113.20": time.Hour})
			}
			results, err := f.e.ApplyBlockBatch([]BlockMember{f.member("act_new", "203.0.113.20")})
			wantEffect := "applied/"
			if reject {
				wantEffect = "failed/"
			}
			if err != nil || effects(results) != wantEffect || f.sends != 1 {
				t.Fatalf("results %+v, error %v, sends %d", results, err, f.sends)
			}
			f.e.mu.Lock()
			stored, ok := f.e.loadStateFileRawLocked()
			f.e.mu.Unlock()
			if !ok || len(stored.BlockedNet) != 1 || stored.BlockedNet[0] != prior.BlockedNet[0] ||
				len(stored.Allowed) != 1 || stored.Allowed[0] != prior.Allowed[0] {
				t.Fatalf("batch lost pending kernel cleanup rows: %+v", stored)
			}
			row, ok := blockedStateEntry(stored, prior.Blocked[0].IP)
			if !ok || !SameBlockedEntry(row, prior.Blocked[0]) {
				t.Fatalf("batch lost the expired block cleanup row: %+v", stored.Blocked)
			}
		})
	}
}
