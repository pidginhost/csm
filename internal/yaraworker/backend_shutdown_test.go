//go:build linux

package yaraworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/workerproc"
)

func TestStopCancelsCompileLaunch(t *testing.T) {
	for _, operation := range []string{"reload", "test compile"} {
		t.Run(operation, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			fx := &backendFixture{compileFn: func(ctx context.Context) (workerproc.Process, error) {
				close(entered)
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-release:
					return nil, errors.New("test released launch")
				}
			}}
			b := newBackend(t, fx)
			done := make(chan struct{})
			var compileErr error
			go func() {
				defer close(done)
				if operation == "reload" {
					compileErr = b.Reload()
				} else {
					compileErr = b.TestCompile("marker:evil\n")
				}
			}()
			t.Cleanup(func() { close(release); <-done })
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("compile did not start")
			}
			stopped := make(chan error, 1)
			go func() { stopped <- b.Stop() }()
			select {
			case err := <-stopped:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("stop blocked on the compile launch")
			}
			select {
			case <-done:
				if compileErr == nil {
					t.Fatal("stopped compile succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("stopping the backend did not cancel its compile launch")
			}
		})
	}
}

func TestTestCompileRefusesAfterStop(t *testing.T) {
	fx := &backendFixture{}
	b := newBackend(t, fx)
	if err := b.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := b.TestCompile("marker:evil\n"); !errors.Is(err, workerproc.ErrStopped) {
		t.Fatalf("compile after stop = %v, want ErrStopped", err)
	}
	if got := fx.compile.launches.Load(); got != 0 {
		t.Fatalf("started %d compile workers after stop", got)
	}
}

func TestReloadContextCancelsWhileCompileBusy(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h := newHelper("worker")
	fx := &backendFixture{compileFn: func(ctx context.Context) (workerproc.Process, error) {
		close(entered)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return h.launch(ctx)
		}
	}}
	b := newBackend(t, fx)
	compiled := make(chan error, 1)
	go func() { compiled <- b.TestCompile("marker:evil\n") }()
	t.Cleanup(func() {
		close(release)
		if err := <-compiled; err != nil {
			t.Errorf("independent compile was interrupted: %v", err)
		}
	})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("compile did not start")
	}
	health := b.CompileError()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reloaded := make(chan error, 1)
	go func() { reloaded <- b.ReloadContext(ctx) }()
	cancel()
	select {
	case err := <-reloaded:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("reload = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled reload waited for another compile")
	}
	if got := b.CompileError(); got != health {
		t.Fatalf("canceled waiter changed compile health from %q to %q", health, got)
	}
}

func TestStopReapsRunningCompiler(t *testing.T) {
	started := make(chan workerproc.Process, 1)
	h := newHelper("compile-hang")
	fx := &backendFixture{compileFn: func(ctx context.Context) (workerproc.Process, error) {
		p, err := h.launch(ctx)
		if err == nil {
			started <- p
		}
		return p, err
	}}
	b := newBackend(t, fx)
	compiled := make(chan error, 1)
	go func() { compiled <- b.Reload() }()
	var p workerproc.Process
	select {
	case p = <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("compiler did not launch")
	}
	t.Cleanup(func() { _ = p.Kill() })
	stopped := make(chan error, 1)
	go func() { stopped <- b.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not terminate the running compiler")
	}
	select {
	case <-p.Done():
	default:
		t.Fatal("stop returned before reaping the compiler")
	}
	if err := <-compiled; err == nil {
		t.Fatal("compile succeeded after stop")
	}
	if b.RuleCount() != 0 {
		t.Fatal("compile installed rules after stop")
	}
}

// Stop must not wait out a scan or a rules load: the daemon stops its
// workers on shutdown, and each can take until its timeout.
func TestStopCancelsInFlightWork(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		call       func(*Backend) error
	}{
		{"scan", "scan-hang:", func(b *Backend) error { _, err := b.ScanBytesChecked([]byte("evil")); return err }},
		{"load before a scan", "load-hang:", func(b *Backend) error { _, err := b.ScanBytesChecked([]byte("evil")); return err }},
		{"load on warm-up", "load-hang:", (*Backend).Warm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mark := filepath.Join(t.TempDir(), "arrived")
			fx := &backendFixture{scan: newHelper(tc.mode + mark)}
			b := newBackend(t, fx)
			if err := b.Reload(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- tc.call(b) }()
			waitForFile(t, mark)
			stopped := make(chan error, 1)
			go func() { stopped <- b.Stop() }()
			select {
			case err := <-stopped:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("stop waited for the worker's timeout")
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("work canceled by stop succeeded")
				}
				if got := b.strikes.Load().Len(); got != 0 {
					t.Fatalf("shutdown struck %d inputs", got)
				}
			case <-time.After(time.Second):
				t.Fatal("work still running after stop")
			}
		})
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
