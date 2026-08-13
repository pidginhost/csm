package state

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClaimRawTimestampAllowsOneConcurrentClaim(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	var claimed atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, claimErr := st.ClaimRawTimestamp("_test_claim", now, time.Hour)
			if claimErr != nil {
				t.Errorf("ClaimRawTimestamp: %v", claimErr)
			}
			if ok {
				claimed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := claimed.Load(); got != 1 {
		t.Fatalf("successful claims = %d, want 1", got)
	}
}

func TestClaimRawTimestampRebasesFutureClock(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	if err := st.SetRawAndSave("_test_clock", now.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if claimed, err := st.ClaimRawTimestamp("_test_clock", now, 24*time.Hour); err != nil || claimed {
		t.Fatalf("future timestamp claim = %v, err = %v, want suppressed rebase", claimed, err)
	}
	if claimed, err := st.ClaimRawTimestamp("_test_clock", now.Add(25*time.Hour), 24*time.Hour); err != nil || !claimed {
		t.Fatalf("post-rebase claim = %v, err = %v, want allowed", claimed, err)
	}
}
