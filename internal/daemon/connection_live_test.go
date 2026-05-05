package daemon

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
)

func TestStartConnectionTrackerBackendSelection(t *testing.T) {
	cases := []struct {
		name     string
		setting  string
		bpfErr   error
		wantMode string
	}{
		{"none returns nil", "none", nil, ""},
		{"auto picks bpf when available", "auto", nil, "bpf"},
		{"auto falls back to legacy on unsupported", "auto", bpf.ErrUnsupported, "legacy"},
		{"auto falls back to legacy on not built", "auto", bpf.ErrNotBuilt, "legacy"},
		{"bpf strict returns nil when unavailable", "bpf", bpf.ErrUnsupported, ""},
		{"legacy pins legacy", "legacy", nil, "legacy"},
		{"unknown falls back to auto", "potato", nil, "bpf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldFn := tryStartConnectionBPFFn
			tryStartConnectionBPFFn = func(_ context.Context, _ chan<- alert.Finding, _ *config.Config) (bpf.Backend, error) {
				if tc.bpfErr != nil {
					return nil, tc.bpfErr
				}
				return &fakeConnBackend{mode: "bpf"}, nil
			}
			defer func() { tryStartConnectionBPFFn = oldFn }()

			cfg := &config.Config{}
			cfg.Detection.ConnectionTrackerBackend = tc.setting
			b := StartConnectionTracker(make(chan alert.Finding, 1), cfg)
			if tc.wantMode == "" {
				if b != nil {
					t.Fatalf("expected nil backend, got %q", b.Mode())
				}
				return
			}
			if b == nil {
				t.Fatal("expected backend, got nil")
			}
			if b.Mode() != tc.wantMode {
				t.Fatalf("Mode = %q, want %q", b.Mode(), tc.wantMode)
			}
		})
	}
}

// fakeConnBackend satisfies bpf.Backend for backend-selection tests.
type fakeConnBackend struct{ mode string }

func (f *fakeConnBackend) Mode() string          { return f.mode }
func (f *fakeConnBackend) EventCount() uint64    { return 0 }
func (f *fakeConnBackend) Run(_ context.Context) {}
