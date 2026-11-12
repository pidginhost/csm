package stalwartsetup

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/stalwartapi"
)

// TestSmokeAgainstStalwart runs setup against a real, throwaway Stalwart.
// It skips unless CSM_STALWART_SMOKE_URL names one; STALWART_USER and
// STALWART_PASSWORD carry its admin login. A stock install binds its HTTP
// listeners on every address, so the client address step must be skipped.
func TestSmokeAgainstStalwart(t *testing.T) {
	url := os.Getenv("CSM_STALWART_SMOKE_URL")
	if url == "" {
		t.Skip("CSM_STALWART_SMOKE_URL is not set")
	}
	ctx := context.Background()
	api := stalwartapi.New(url, os.Getenv("STALWART_USER"), os.Getenv("STALWART_PASSWORD"))
	in := Inputs{BlockExpiry: 24 * time.Hour}

	p, err := Inspect(ctx, api, in)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	warnings, err := p.Apply(ctx, api)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	t.Logf("reload warnings: %q", warnings)

	p, err = Inspect(ctx, api, in)
	if err != nil {
		t.Fatalf("second Inspect: %v", err)
	}
	want := []State{Done, Skipped, Done, Done}
	for i, s := range p.Steps {
		t.Logf("%s: %s: %s", s.Name, s.State, s.Detail)
		if s.State != want[i] {
			t.Errorf("%s = %s, want %s", s.Name, s.State, want[i])
		}
	}
}
