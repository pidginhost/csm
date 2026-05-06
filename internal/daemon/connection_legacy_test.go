package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestConnectionPollerStopsOnContextCancel(t *testing.T) {
	cfg := &config.Config{}

	ch := make(chan alert.Finding, 4)
	p := newConnectionPoller(cfg, ch)
	if p.Mode() != "legacy" {
		t.Fatalf("Mode = %q, want legacy", p.Mode())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return within 1s of ctx cancel")
	}
}
