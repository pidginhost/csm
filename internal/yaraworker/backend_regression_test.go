//go:build linux

package yaraworker

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/workerproc"
)

func TestBackendAllRulesDisabled(t *testing.T) {
	fx := &backendFixture{
		dir:      rulesDir(t, map[string]string{"rules.yar": "rule drop_me {\nmarker:evil\n}\n"}),
		disabled: []string{"drop_me"},
	}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if b.RuleCount() != 0 || b.CompileError() != "" {
		t.Fatalf("RuleCount=%d CompileError=%q", b.RuleCount(), b.CompileError())
	}
	if matches, err := b.ScanFDChecked(tempFile(t, "evil"), 4); err == nil {
		t.Errorf("descriptor scan with all rules disabled read clean: %v", matches)
	}
	if matches, err := b.ScanBytesChecked([]byte("evil")); err != nil || matches != nil {
		t.Errorf("byte scan with all rules disabled = %v, %v; want clean", matches, err)
	}
	if n := fx.scan.launches.Load(); n != 0 {
		t.Errorf("scans without rules started %d workers", n)
	}
}

func TestBackendStopDuringReload(t *testing.T) {
	started, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	h := newHelper("worker")
	fx := &backendFixture{compileFn: func(ctx context.Context) (workerproc.Process, error) {
		close(started)
		<-resume
		return h.launch(ctx)
	}}
	b := newBackend(t, fx)
	t.Cleanup(release)
	done := make(chan error, 1)
	go func() { done <- b.Reload() }()
	<-started
	stopErr := b.Stop()
	release()
	if stopErr != nil {
		t.Fatal(stopErr)
	}
	if err := <-done; !errors.Is(err, workerproc.ErrStopped) {
		t.Errorf("reload finishing after Stop = %v, want ErrStopped", err)
	}
	if rules := b.current(); rules != nil {
		t.Error("reload published an open rules descriptor after Stop")
	}
}

func TestBackendStoppedRejectsWork(t *testing.T) {
	fx := &backendFixture{}
	b := newBackend(t, fx)
	if err := b.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := b.TestCompile("marker:evil\n"); !errors.Is(err, workerproc.ErrStopped) {
		t.Errorf("TestCompile after Stop = %v, want ErrStopped", err)
	}
	if err := b.Reload(); !errors.Is(err, workerproc.ErrStopped) {
		t.Errorf("Reload after Stop = %v, want ErrStopped", err)
	}
	if _, err := b.ScanBytesChecked([]byte("evil")); !errors.Is(err, workerproc.ErrStopped) {
		t.Errorf("ScanBytesChecked after Stop = %v, want ErrStopped", err)
	}
	if _, err := b.ScanFDChecked(tempFile(t, "evil"), 4); !errors.Is(err, workerproc.ErrStopped) {
		t.Errorf("ScanFDChecked after Stop = %v, want ErrStopped", err)
	}
	if n := fx.compile.launches.Load(); n != 0 {
		t.Errorf("stopped backend started %d compile workers", n)
	}
}

func TestBackendLoadFailureClosesConnection(t *testing.T) {
	h := newHelper("load-error")
	var p workerproc.Process
	fx := &backendFixture{scanFn: func(ctx context.Context) (workerproc.Process, error) {
		var err error
		p, err = h.launch(ctx)
		return p, err
	}}
	b := newBackend(t, fx)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ScanBytesChecked([]byte("evil")); err == nil {
		t.Fatal("load failure was accepted")
	}
	if p == nil {
		t.Fatal("scan worker never started")
	}
	t.Cleanup(func() { _ = p.Conn().Close() })
	if err := p.Conn().SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("failed worker connection remains open: %v", err)
	}
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("failed worker was not reaped")
	}
}

func TestBackendRejectsInvalidCompileCounts(t *testing.T) {
	for _, mode := range []string{"compile-negative", "compile-missing-count", "compile-null-count", "compile-null", "compile-error-count"} {
		t.Run(mode, func(t *testing.T) {
			// A stripped rule permits a valid empty compilation, so a missing
			// count must not be confused with that legitimate zero.
			fx := &backendFixture{
				dir:      rulesDir(t, map[string]string{"rules.yar": "marker:evil\nrule drop_me {\nmarker:other\n}\n"}),
				disabled: []string{"drop_me"},
			}
			b := newBackend(t, fx)
			if err := b.Reload(); err != nil {
				t.Fatal(err)
			}
			fx.compile.setMode(mode)
			if err := b.Reload(); workerproc.FailureReason(err) != workerproc.ReasonProtocol {
				t.Errorf("invalid compile reply = %v, want protocol failure", err)
			}
			if b.RuleCount() != 1 || b.CompileError() != "" {
				t.Fatalf("invalid compile reply replaced the rules: count=%d error=%q", b.RuleCount(), b.CompileError())
			}
			if names := ruleNames(t, b, "evil"); len(names) != 1 || names[0] != "evil" {
				t.Fatalf("old rules not usable after invalid reply: %v", names)
			}
		})
	}
}

func TestBackendWarmRejectsInvalidCounts(t *testing.T) {
	for _, mode := range []string{"ping-negative", "ping-missing-count", "ping-null-count", "ping-null"} {
		t.Run(mode, func(t *testing.T) {
			fx := &backendFixture{scan: newHelper(mode)}
			b := newBackend(t, fx)
			if err := b.Reload(); err != nil {
				t.Fatal(err)
			}
			if err := b.Warm(); workerproc.FailureReason(err) != workerproc.ReasonProtocol {
				t.Errorf("invalid ping reply = %v, want protocol failure", err)
			}
			if b.Stats().Running {
				t.Error("worker with an invalid readiness reply remains running")
			}
		})
	}
}

func TestBackendLoadRequiresExplicitZeroCount(t *testing.T) {
	b := newBackend(t, &backendFixture{})
	p, err := newHelper("load-missing-count").launch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = p.Kill()
		_ = p.Conn().Close()
		<-p.Done()
	})
	if err := b.loadRules(context.Background(), p, memfd(t, fakeRulesHeader), 0); err == nil {
		t.Fatal("missing load count accepted as an explicit empty ruleset")
	}
}

func TestBackendReloadWhileWorkerStarts(t *testing.T) {
	started, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	h := newHelper("worker")
	fx := &backendFixture{scanFn: func(ctx context.Context) (workerproc.Process, error) {
		if h.launches.Load() == 0 {
			close(started)
			<-resume
		}
		return h.launch(ctx)
	}}
	b := newBackend(t, fx)
	t.Cleanup(release)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		matches, err := b.ScanBytesChecked([]byte("evil"))
		if err == nil && (len(matches) != 1 || matches[0].RuleName != "evil") {
			err = errors.New("the in-flight scan lost its rules")
		}
		done <- err
	}()
	<-started
	writeRule(t, fx.dir, "rules.yar", "marker:other\n")
	reloadErr := b.Reload()
	release()
	if reloadErr != nil {
		t.Fatal(reloadErr)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if names := ruleNames(t, b, "other evil"); len(names) != 1 || names[0] != "other" {
		t.Fatalf("scan after concurrent reload = %v, want only other", names)
	}
	if n := h.launches.Load(); n != 2 {
		t.Errorf("scan launches = %d, want 2", n)
	}
}
