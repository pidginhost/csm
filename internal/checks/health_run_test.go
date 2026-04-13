package checks

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestCheckHealthRuns(t *testing.T) {
	cfg := &config.Config{}
	findings := CheckHealth(context.Background(), cfg, nil)
	// On dev machines, some commands won't be found — that's expected.
	// The test verifies the function runs without panicking.
	_ = findings
}
