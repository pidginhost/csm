package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/antispam/reconcile"
	"github.com/pidginhost/csm/internal/eximlock"
)

func TestInvalidateCanceledDuringStagingPreservesRequest(t *testing.T) {
	for _, busy := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "busy"}[busy], func(t *testing.T) {
			prevDir, prevStage, prevSync := requestDir, stageRecord, syncRecordDir
			requestDir = t.TempDir()
			t.Cleanup(func() { requestDir, stageRecord, syncRecordDir = prevDir, prevStage, prevSync })
			previous := []byte(applyBody)
			if recorded, err := recordRequest(context.Background(), requestDir, previous); err != nil || !recorded {
				t.Fatalf("recorded=%v err=%v", recorded, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stageRecord = func(path string, body []byte) (string, error) {
				tmp, err := prevStage(path, body)
				cancel()
				return tmp, err
			}
			synced := 0
			syncRecordDir = func(dir string) error { synced++; return prevSync(dir) }
			invalidate := func() error { return Invalidate(ctx) }
			var err error
			if busy {
				err = eximlock.With(requestDir, invalidate)
			} else {
				err = invalidate()
			}
			if !errors.Is(err, context.Canceled) || synced != 0 {
				t.Errorf("err=%v synced=%d, want cancellation without publication", err, synced)
			}
			got, err := os.ReadFile(filepath.Join(requestDir, RequestFile))
			if err != nil || !bytes.Equal(got, previous) {
				t.Errorf("canceled invalidation replaced pending request with %q: %v", got, err)
			}
			entries, err := os.ReadDir(requestDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 2 {
				t.Errorf("left unpublished files behind: %v", entries)
			}
		})
	}
}

// A short request publication by forward guard must not defer an antispam
// reload for the full busy retry interval.
func TestInvalidateWaitsOutABriefHolder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		prev := requestDir
		requestDir = t.TempDir()
		defer func() { requestDir = prev }()
		var reads atomic.Int32
		r := reconcile.Reconciler{
			Invalidate: Invalidate,
			Installed: func() antispam.HostFacts {
				reads.Add(1)
				return antispam.HostFacts{Record: antispam.RecordFacts{Missing: true}}
			},
			Now: time.Now,
		}
		finished := make(chan reconcile.Outcome, 1)
		if err := eximlock.With(requestDir, func() error {
			go func() { finished <- r.Pass(context.Background(), reconcile.Desired{}) }()
			synctest.Wait()
			if reads.Load() != 0 {
				t.Error("pass read the host while a transaction held the lock")
			}
			time.Sleep(50 * time.Millisecond)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		out := <-finished
		if out.Err != nil || out.Retry != 0 || len(out.Findings) != 0 || len(out.Checks) != 3 || reads.Load() != 1 {
			t.Errorf("pass after a brief lock: outcome=%+v reads=%d", out, reads.Load())
		}
	})
}
