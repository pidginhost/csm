package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/eximlock"
)

func TestRecordRequestFlushesPublicationUnlocked(t *testing.T) {
	dir := t.TempDir()
	prev := syncRecordDir
	t.Cleanup(func() { syncRecordDir = prev })
	synced := 0
	syncRecordDir = func(path string) error {
		synced++
		if path != dir {
			t.Fatalf("flushing %q, want %q", path, dir)
		}
		if err := eximlock.With(dir, func() error {
			got, err := os.ReadFile(filepath.Join(dir, RequestFile))
			if err != nil || string(got) != applyBody {
				t.Errorf("directory flush preceded publication: record=%q err=%v", got, err)
			}
			return nil
		}); err != nil {
			t.Errorf("lock held while flushing directory: %v", err)
		}
		return prev(path)
	}
	recorded, err := recordRequest(context.Background(), dir, []byte(applyBody))
	if !recorded || err != nil || synced != 1 {
		t.Fatalf("recorded=%v err=%v synced=%d", recorded, err, synced)
	}
}

func TestRecordDirectoryFlushFailureStopsCallers(t *testing.T) {
	for _, caller := range []string{"run", "invalidate"} {
		t.Run(caller, func(t *testing.T) {
			mark := launchMarker(t)
			prev := syncRecordDir
			t.Cleanup(func() { syncRecordDir = prev })
			failure := errors.New("directory flush failed")
			synced := 0
			syncRecordDir = func(string) error { synced++; return failure }
			var err error
			if caller == "run" {
				var result antispam.Result
				result, err = Run(context.Background(), antispam.RemoveRequest())
				if result != (antispam.Result{}) {
					t.Errorf("recording failure returned a worker result: %+v", result)
				}
			} else {
				err = Invalidate(context.Background())
			}
			if !errors.Is(err, failure) || synced != 1 {
				t.Errorf("err=%v synced=%d", err, synced)
			}
			assertNoLaunch(t, mark)
		})
	}
}
