//go:build linux

package yaraworker

import (
	"context"
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/workerproc"
)

// The compile supervisor stops its child after accepting and copying the
// compiled rules. Cancel there to exercise the gap before Reload installs them.
type cancelOnCompilerStop struct {
	workerproc.Process
	cancel context.CancelFunc
}

func (p *cancelOnCompilerStop) Kill() error {
	p.cancel()
	return p.Process.Kill()
}

func TestReloadCanceledAfterCompilePreservesScanState(t *testing.T) {
	for _, loaded := range []bool{false, true} {
		name := "fresh"
		if loaded {
			name = "loaded"
		}
		t.Run(name, func(t *testing.T) {
			fx := &backendFixture{}
			b := newBackend(t, fx)
			if loaded {
				if err := b.Reload(); err != nil {
					t.Fatal(err)
				}
			}
			previous := b.current()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b.cfg.CompileLaunch = func(ctx context.Context) (workerproc.Process, error) {
				p, err := fx.compile.launch(ctx)
				if err != nil {
					return nil, err
				}
				return &cancelOnCompilerStop{Process: p, cancel: cancel}, nil
			}
			writeRule(t, fx.dir, "rules.yar", "marker:replacement\n")
			if err := b.ReloadContext(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("reload = %v, want context.Canceled", err)
			}
			if b.current() != previous {
				t.Fatal("canceled reload installed its compiled rules")
			}
			if loaded {
				if got := ruleNames(t, b, "evil replacement"); len(got) != 1 || got[0] != "evil" {
					t.Fatalf("canceled reload did not retain the old detection: %v", got)
				}
				if got := b.CompileError(); got != "" {
					t.Fatalf("canceled reload marked usable rules unavailable: %q", got)
				}
			} else {
				if m, err := b.ScanBytesChecked([]byte("replacement")); err == nil {
					t.Fatalf("canceled first compile allowed a clean scan: %+v", m)
				}
				if b.CompileError() == "" {
					t.Fatal("canceled first compile cleared the unavailable status")
				}
			}
			b.cfg.CompileLaunch = fx.compile.launch
			if err := b.Reload(); err != nil {
				t.Fatal(err)
			}
			if got := ruleNames(t, b, "evil replacement"); len(got) != 1 || got[0] != "replacement" {
				t.Fatalf("retry did not install the new detection: %v", got)
			}
		})
	}
}
