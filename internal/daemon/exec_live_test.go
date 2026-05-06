package daemon

import (
	"context"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
)

func TestStartExecMonitorBackendSelection(t *testing.T) {
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
			oldFn := tryStartExecBPFFn
			tryStartExecBPFFn = func(_ context.Context, _ chan<- alert.Finding, _ *config.Config) (bpf.Backend, error) {
				if tc.bpfErr != nil {
					return nil, tc.bpfErr
				}
				return &fakeConnBackend{mode: "bpf"}, nil
			}
			defer func() { tryStartExecBPFFn = oldFn }()

			cfg := &config.Config{}
			cfg.Detection.ExecMonitorBackend = tc.setting
			b := StartExecMonitor(make(chan alert.Finding, 1), cfg)
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
