package stalwartapi

import (
	"context"
	"os"
	"testing"
)

// TestSmokeBlocklistProbe sends the blocklist probe to a real, throwaway
// Stalwart. It skips unless CSM_STALWART_SMOKE_URL names one; STALWART_USER
// and STALWART_PASSWORD carry its admin login.
func TestSmokeBlocklistProbe(t *testing.T) {
	url := os.Getenv("CSM_STALWART_SMOKE_URL")
	if url == "" {
		t.Skip("CSM_STALWART_SMOKE_URL is not set")
	}
	c := New(url, os.Getenv("STALWART_USER"), os.Getenv("STALWART_PASSWORD"))
	got, err := c.ClassifySpam(context.Background(), BlocklistProbe)
	if err != nil {
		t.Fatalf("ClassifySpam: %v", err)
	}
	if got.Result == "" {
		t.Fatal("the probe returned no result")
	}
	t.Logf("score %v, result %s, tags %q", got.Score, got.Result, got.Tags)
}
