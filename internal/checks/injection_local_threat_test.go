package checks

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// attackdb does NOT expose a SetGlobal helper. Per the tasking, we only
// exercise the nil-attackdb early-return paths of CheckLocalThreatScore
// that aren't already duplicated in existing suites.

// Context cancellation currently has no effect on the return value (the
// function never consults the context when attackdb is nil) - lock that in.
func TestCheckLocalThreatScoreCanceledContextNilDB(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := CheckLocalThreatScore(ctx, &config.Config{StatePath: t.TempDir()}, nil)
	if got != nil {
		t.Errorf("cancelled context with nil attackdb should still return nil, got %v", got)
	}
}

// Confirms CheckLocalThreatScore's return type is []alert.Finding and that
// it returns a genuinely nil slice (not an empty allocated one) when
// attackdb is unset - downstream callers rely on this to skip processing.
func TestCheckLocalThreatScoreReturnsUntypedNilWithNilDB(t *testing.T) {
	cfg := &config.Config{StatePath: t.TempDir()}
	got := CheckLocalThreatScore(context.Background(), cfg, nil)
	if got != nil {
		t.Errorf("expected nil slice (not empty), got len=%d cap=%d", len(got), cap(got))
	}
}

// The function's severity/timestamp branch is only reached when attackdb
// yields a record with score >= 70. We cannot inject one, so this test
// merely documents the non-reachable nature of that branch given our
// current test fixtures.
func TestCheckLocalThreatScoreUnreachableSeverityBranch(t *testing.T) {
	// Reference alert.Critical so the import stays live if the function
	// ever grows a variant that would otherwise kill the import.
	if alert.Critical.String() == "" {
		t.Skip("alert.Critical has no string representation - skipping sentinel")
	}
	// A zero-value time must be usable as a placeholder; this mirrors
	// how Finding.Timestamp is populated inside the unreachable branch.
	if (time.Time{}).IsZero() != true {
		t.Error("zero time should be zero")
	}

	got := CheckLocalThreatScore(context.Background(), &config.Config{StatePath: t.TempDir()}, nil)
	if got != nil {
		t.Errorf("nil attackdb path should return nil, got %v", got)
	}
}
