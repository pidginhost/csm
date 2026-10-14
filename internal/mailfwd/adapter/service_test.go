package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/eximlock"
	"github.com/pidginhost/csm/internal/mailfwd/policy"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/systemdrun"
)

func mutationBody(t *testing.T, request eximMutation) string {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mutationTarget(target ForwardGuard) func(eximMutation) error {
	return func(r eximMutation) error { return r.applyTo(target) }
}

func TestEximMutationPreservesTransaction(t *testing.T) {
	a, side := testAdapter(t)
	original := platform.EximLocalSkeleton + "# operator setting\n"
	if err := os.WriteFile(a.localConf, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	request := eximMutation{Operation: "apply", Config: policy.Config{Enabled: true, HoldSignals: policy.HoldSignals{BounceBackscatter: true}}, BadIPs: []string{"192.0.2.1"}}
	body := mutationBody(t, request)
	if err := handleEximMutation(strings.NewReader(body), mutationTarget(a)); err != nil {
		t.Fatal(err)
	}
	status, err := a.Status()
	if err != nil || !status.Installed || side.rebuilds != 1 {
		t.Fatalf("status=%+v error=%v rebuilds=%d", status, err, side.rebuilds)
	}
	if err = handleEximMutation(strings.NewReader(`{"operation":"remove"}`), mutationTarget(a)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(a.localConf)
	if err != nil || string(data) != original || side.rebuilds != 2 {
		t.Fatalf("remove lost operator config: %s %v rebuilds=%d", data, err, side.rebuilds)
	}
	failure := errors.New("rebuild failed")
	calls := 0
	a.rebuild = func() error {
		calls++
		if calls == 1 {
			return failure
		}
		return nil
	}
	if err = handleEximMutation(strings.NewReader(body), mutationTarget(a)); !errors.Is(err, failure) {
		t.Fatalf("error=%v", err)
	}
	data, err = os.ReadFile(a.localConf)
	if err != nil || string(data) != original || calls != 2 {
		t.Fatalf("rollback failed: %s %v calls=%d", data, err, calls)
	}
}

func TestEximMutationRejectsInvalidRequestsBeforeSideEffects(t *testing.T) {
	cases := []string{
		``, `null`, `{}`, `{"operation":"shell"}`, `{"operation":"remove","path":"/etc/passwd"}`,
		`{"operation":"remove"} {}`, `{"operation":"remove"} junk`,
		`{"operation":"apply","config":{"Enabled":true,"DryRun":true}}`,
		`{"operation":"apply","config":{"Enabled":true}}`,
		`{"operation":"apply","config":{"Enabled":true,"HoldSignals":{"BounceBackscatter":true}},"bad_ips":["192.0.2.1\ncommand"]}`,
		`{"operation":"remove","bad_ips":["192.0.2.1"]}`,
		strings.Repeat(" ", eximMutationLimit+1),
	}
	for i, input := range cases {
		a, side := testAdapter(t)
		if err := handleEximMutation(strings.NewReader(input), mutationTarget(a)); err == nil {
			t.Errorf("case %d accepted", i)
		}
		entries, err := os.ReadDir(strings.TrimSuffix(a.localConf, "/exim.conf.local"))
		if err != nil || len(entries) != 0 || side.rebuilds != 0 {
			t.Fatalf("case %d had side effects: %+v %v", i, entries, err)
		}
	}
	readErr := errors.New("read failed")
	if err := handleEximMutation(errorReader{readErr}, nil); !errors.Is(err, readErr) {
		t.Fatalf("read error=%v", err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func TestEximServiceAdapterDelegatesMutationsOnly(t *testing.T) {
	a, side := testAdapter(t)
	writeInstalledConf(t, a)
	var got []eximMutation
	service := &eximServiceAdapter{EximAdapter: a, mutate: func(r eximMutation) error { got = append(got, r); return io.ErrClosedPipe }}
	cfg := policy.Config{Enabled: true, HoldSignals: policy.HoldSignals{BounceBackscatter: true}}
	ips := []string{"192.0.2.9"}
	if err := service.Apply(cfg, ips); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if err := service.Remove(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].RequestID == "" || got[1].RequestID == "" || got[0].RequestID == got[1].RequestID || !reflect.DeepEqual(got, []eximMutation{{RequestID: got[0].RequestID, Operation: "apply", Config: cfg, BadIPs: ips}, {RequestID: got[1].RequestID, Operation: "remove"}}) {
		t.Fatalf("requests=%+v", got)
	}
	if err := service.RefreshBadIPs(ips); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(a.badIPsPath)
	if err != nil || string(data) != "192.0.2.9: 1\n" {
		t.Fatalf("lookup=%s %v", data, err)
	}
	status, err := service.Status()
	if err != nil || !status.Installed || side.rebuilds != 0 || len(got) != 2 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestEximServiceUsesFixedBoundedTransientCommand(t *testing.T) {
	failure := errors.New("worker failed")
	var calls [][]string
	err := executeEximMutation(context.Background(), "/opt/csm/csm", func(string) (string, error) { return "/usr/bin/systemd-run", nil }, func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if len(calls) == 2 {
			return []byte("rollback complete"), failure
		}
		return nil, nil
	})
	want := [][]string{
		{"/usr/bin/systemd-run", "--quiet", "--collect", "--pipe", "--property=RuntimeMaxSec=300s", "--", "/bin/true"},
		{"/usr/bin/systemd-run", "--quiet", "--collect", "--pipe", "--property=RuntimeMaxSec=300s", "--", "/opt/csm/csm", "forward-guard-worker"},
	}
	if !errors.Is(err, failure) || !strings.Contains(err.Error(), "rollback complete") || !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%q error=%v", calls, err)
	}
}

// writeInstalledConf puts both managed blocks into exim.conf.local, as an
// earlier apply would, without a rebuild.
func writeInstalledConf(t *testing.T, a *EximAdapter) string {
	t.Helper()
	router, err := a.renderRouter(policy.HoldSignals{BounceBackscatter: true})
	if err != nil {
		t.Fatal(err)
	}
	conf, err := injectBlock(platform.EximLocalSkeleton, "@ROUTERSTART@", router)
	if err == nil {
		conf, err = injectBlock(conf, "@TRANSPORTSTART@", a.renderTransport())
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.localConf, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	return conf
}

// A stable absence needs no root worker or rebuild on config reload.
func TestEximServiceAdapterRemoveSkipsWorkerWhenNothingInstalled(t *testing.T) {
	for name, setup := range map[string]func(*testing.T, *EximAdapter){
		"no file": func(*testing.T, *EximAdapter) {},
		"no blocks": func(t *testing.T, a *EximAdapter) {
			if err := os.WriteFile(a.localConf, []byte(platform.EximLocalSkeleton+"# operator setting\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, side := testAdapter(t)
			setup(t, a)
			calls := 0
			service := &eximServiceAdapter{EximAdapter: a, mutate: func(eximMutation) error { calls++; return io.ErrClosedPipe }}
			if err := service.Remove(); err != nil || calls != 0 || side.rebuilds != 0 {
				t.Fatalf("err=%v worker calls=%d rebuilds=%d", err, calls, side.rebuilds)
			}
		})
	}
}

// An inconclusive status still goes to the root worker, which may have
// access the daemon lacks.
func TestEximServiceAdapterRemoveRunsWorkerUnlessProvenAbsent(t *testing.T) {
	for name, setup := range map[string]func(*testing.T, *EximAdapter){
		"installed": func(t *testing.T, a *EximAdapter) { writeInstalledConf(t, a) },
		"partial": func(t *testing.T, a *EximAdapter) {
			conf := stripBlock(writeInstalledConf(t, a), transportBegin, transportEnd)
			if err := os.WriteFile(a.localConf, []byte(conf), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"unreadable": func(t *testing.T, a *EximAdapter) {
			if err := os.Mkdir(a.localConf, 0o755); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, _ := testAdapter(t)
			setup(t, a)
			var got []eximMutation
			service := &eximServiceAdapter{EximAdapter: a, mutate: func(r eximMutation) error { got = append(got, r); return io.ErrClosedPipe }}
			if err := service.Remove(); !errors.Is(err, io.ErrClosedPipe) || len(got) != 1 || got[0].RequestID == "" || !reflect.DeepEqual(got, []eximMutation{{RequestID: got[0].RequestID, Operation: "remove"}}) {
				t.Fatalf("err=%v requests=%+v", err, got)
			}
		})
	}
}

// The worker's exit status tells a busy Exim lock apart from a failed change.
func TestWorkerExitCodeSeparatesBusyFromFailure(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{nil, 0},
		{fmt.Errorf("%w: resource temporarily unavailable", eximlock.ErrBusy), workerBusyExit},
		{errors.New("buildeximconf failed"), 1},
	} {
		if got := WorkerExitCode(tc.err); got != tc.want {
			t.Errorf("WorkerExitCode(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}

// A request refused at the lock ends with the busy status and changes nothing.
func TestEximMutationRefusedAtTheLockExitsBusy(t *testing.T) {
	a, side := testAdapter(t)
	writeInstalledConf(t, a)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- eximlock.With(filepath.Dir(a.badIPsPath), func() error { close(entered); <-release; return nil })
	}()
	<-entered
	busyErr := handleEximMutation(strings.NewReader(`{"operation":"remove"}`), lockedEximAdapter{a}.mutate)
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if code := WorkerExitCode(busyErr); code != workerBusyExit || side.rebuilds != 0 {
		t.Fatalf("exit=%d err=%v rebuilds=%d", code, busyErr, side.rebuilds)
	}
	if code := WorkerExitCode(handleEximMutation(strings.NewReader(`{"operation":"remove"}`), lockedEximAdapter{a}.mutate)); code != 0 || side.rebuilds != 1 {
		t.Fatalf("unlocked remove exit=%d rebuilds=%d", code, side.rebuilds)
	}
}

// The daemon reads the busy status as eximlock.ErrBusy whether the worker ran
// through systemd-run or directly. Any other exit stays a failure that carries
// the worker's output.
func TestEximServiceSeparatesBusyWorkerFromFailedWorker(t *testing.T) {
	lookups := map[string]systemdrun.LookPathFunc{
		"systemd-run": func(string) (string, error) { return "/usr/bin/systemd-run", nil },
		"direct":      func(string) (string, error) { return "", exec.ErrNotFound },
	}
	for path, lookup := range lookups {
		for _, code := range []int{workerBusyExit, 1} {
			t.Run(fmt.Sprintf("%s/exit-%d", path, code), func(t *testing.T) {
				// A real child process, so the runner returns a real *exec.ExitError.
				run := func(ctx context.Context, _ string, args ...string) ([]byte, error) {
					if len(args) > 0 && args[len(args)-1] == "/bin/true" {
						return nil, nil // systemd-run availability probe
					}
					return exec.CommandContext(ctx, "/bin/sh", "-c", fmt.Sprintf("echo worker output; exit %d", code)).CombinedOutput()
				}
				err := executeEximMutation(context.Background(), "/opt/csm/csm", lookup, run)
				busy := code == workerBusyExit
				if err == nil || errors.Is(err, eximlock.ErrBusy) != busy {
					t.Fatalf("err=%v, want busy=%v", err, busy)
				}
				if !busy && !strings.Contains(err.Error(), "worker output") {
					t.Fatalf("failure lost the worker output: %v", err)
				}
			})
		}
	}
}

// A transient worker can outlive its daemon. A new daemon must retry removal
// if that worker can still install the guard or restore it during rollback.
func TestEximServiceAdapterRemoveRetriesUnfinishedWorker(t *testing.T) {
	for _, operation := range []string{"apply", "remove rollback"} {
		t.Run(operation, func(t *testing.T) {
			a, _ := testAdapter(t)
			worker := lockedEximAdapter{a}
			cfg := policy.Config{Enabled: true, HoldSignals: policy.HoldSignals{BounceBackscatter: true}}
			entered, release := make(chan struct{}), make(chan struct{})
			failure := errors.New("rebuild failed")
			var run func() error
			if operation == "apply" {
				a.chown = func(string, string) error {
					close(entered)
					<-release
					return nil
				}
				run = func() error { return worker.mutate(eximMutation{Operation: "apply", Config: cfg}) }
			} else {
				if err := worker.mutate(eximMutation{Operation: "apply", Config: cfg}); err != nil {
					t.Fatal(err)
				}
				calls := 0
				a.rebuild = func() error {
					calls++
					if calls == 1 {
						close(entered)
						<-release
						return failure
					}
					return nil
				}
				run = func() error { return worker.mutate(eximMutation{Operation: "remove"}) }
			}
			finished := make(chan error, 1)
			go func() { finished <- run() }()
			select {
			case <-entered:
			case err := <-finished:
				t.Fatalf("worker finished before reaching the barrier: %v", err)
			}
			status, statusErr := a.Status()
			service := &eximServiceAdapter{EximAdapter: a, mutate: func(r eximMutation) error {
				if r.Operation != "remove" {
					return errors.New("unexpected operation: " + r.Operation)
				}
				return worker.mutate(r)
			}}
			removeErr := service.Remove()
			close(release)
			workerErr := <-finished
			if statusErr != nil || status.Installed {
				t.Fatalf("guard must be absent during transaction: %+v, %v", status, statusErr)
			}
			if operation == "apply" && workerErr != nil || operation == "remove rollback" && !errors.Is(workerErr, failure) {
				t.Fatalf("worker error = %v", workerErr)
			}
			if status, err := a.Status(); err != nil || !status.Installed {
				t.Fatalf("worker did not leave an installed guard: %+v, %v", status, err)
			}
			if !errors.Is(removeErr, eximlock.ErrBusy) {
				t.Fatalf("remove error = %v, want busy so the daemon retries", removeErr)
			}
			if err := service.Remove(); err != nil {
				t.Fatalf("retry removal: %v", err)
			}
			if status, err := a.Status(); err != nil || status.Installed {
				t.Fatalf("retry left guard installed: %+v, %v", status, err)
			}
		})
	}
}

// While another CSM transaction holds the lock, the daemon defers the
// request and starts no worker, for an install and for a removal alike.
func TestEximServiceAdapterStartsNoWorkerWhileLockIsHeld(t *testing.T) {
	a, _ := testAdapter(t)
	writeInstalledConf(t, a)
	calls := 0
	service := &eximServiceAdapter{EximAdapter: a, mutate: func(eximMutation) error { calls++; return nil }}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- eximlock.With(filepath.Dir(a.badIPsPath), func() error { close(entered); <-release; return nil })
	}()
	<-entered
	applyErr := service.Apply(policy.Config{Enabled: true, HoldSignals: policy.HoldSignals{BounceBackscatter: true}}, nil)
	removeErr := service.Remove()
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(applyErr, eximlock.ErrBusy) || !errors.Is(removeErr, eximlock.ErrBusy) || calls != 0 {
		t.Fatalf("apply=%v remove=%v worker calls=%d", applyErr, removeErr, calls)
	}
}

// A request the daemon cannot record starts no worker: the worker could not
// tell whether it is still the latest. It is a failure, not a busy lock.
func TestEximServiceAdapterStartsNoWorkerForAnUnrecordedRequest(t *testing.T) {
	a, _ := testAdapter(t)
	writeInstalledConf(t, a)
	if err := os.WriteFile(filepath.Dir(a.badIPsPath), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	service := &eximServiceAdapter{EximAdapter: a, mutate: func(eximMutation) error { calls++; return nil }}
	applyErr := service.Apply(policy.Config{Enabled: true, HoldSignals: policy.HoldSignals{BounceBackscatter: true}}, nil)
	removeErr := service.Remove()
	if applyErr == nil || removeErr == nil || errors.Is(applyErr, eximlock.ErrBusy) || errors.Is(removeErr, eximlock.ErrBusy) || calls != 0 {
		t.Fatalf("apply=%v remove=%v worker calls=%d", applyErr, removeErr, calls)
	}
}

// A worker started before a daemon restart can reach the lock after the new
// daemon has decided. It must change nothing and report busy; the newer
// request, or the new daemon's absence check, owns the result.
func TestEximServiceStaleWorkerFromBeforeARestartChangesNothing(t *testing.T) {
	cfg := policy.Config{Enabled: true, HoldSignals: policy.HoldSignals{BounceBackscatter: true}}
	for name, tc := range map[string]struct {
		installed     bool
		before, after func(ForwardGuard) error
	}{
		"install after the guard was turned off": {
			installed: false,
			before:    func(g ForwardGuard) error { return g.Apply(cfg, nil) },
			after:     func(g ForwardGuard) error { return g.Remove() },
		},
		"removal after the guard was turned on": {
			installed: true,
			before:    func(g ForwardGuard) error { return g.Remove() },
			after:     func(g ForwardGuard) error { return g.Apply(cfg, nil) },
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, side := testAdapter(t)
			if tc.installed {
				writeInstalledConf(t, a)
			}
			worker := func(r eximMutation) error {
				return handleEximMutation(strings.NewReader(mutationBody(t, r)), lockedEximAdapter{a}.mutate)
			}
			var stale []eximMutation
			oldDaemon := &eximServiceAdapter{EximAdapter: a, mutate: func(r eximMutation) error { stale = append(stale, r); return nil }}
			if err := tc.before(oldDaemon); err != nil || len(stale) != 1 {
				t.Fatalf("old daemon: err=%v requests=%+v", err, stale)
			}
			newDaemon := &eximServiceAdapter{EximAdapter: a, mutate: worker}
			if err := tc.after(newDaemon); err != nil {
				t.Fatalf("new daemon: %v", err)
			}
			rebuilds := side.rebuilds
			staleErr := worker(stale[0])
			status, err := a.Status()
			if !errors.Is(staleErr, errSuperseded) || WorkerExitCode(staleErr) != workerBusyExit || err != nil || status.Installed != tc.installed || side.rebuilds != rebuilds {
				t.Fatalf("stale worker: err=%v exit=%d installed=%v (want %v) rebuilds %d to %d", staleErr, WorkerExitCode(staleErr), status.Installed, tc.installed, rebuilds, side.rebuilds)
			}
		})
	}
}

// A worker whose daemon predates the request record still runs its request.
func TestEximMutationWithoutARecordedRequestRuns(t *testing.T) {
	a, side := testAdapter(t)
	request := eximMutation{Operation: "apply", Config: policy.Config{Enabled: true, HoldSignals: policy.HoldSignals{BounceBackscatter: true}}}
	if err := handleEximMutation(strings.NewReader(mutationBody(t, request)), lockedEximAdapter{a}.mutate); err != nil {
		t.Fatal(err)
	}
	if status, err := a.Status(); err != nil || !status.Installed || side.rebuilds != 1 {
		t.Fatalf("status=%+v err=%v rebuilds=%d", status, err, side.rebuilds)
	}
}

// Equal settings do not make an old worker current again: it must not
// rebuild Exim or replace sender intelligence refreshed by the new daemon.
func TestEximServiceIdenticalRequestSupersedesOldWorker(t *testing.T) {
	a, side := testAdapter(t)
	cfg := bothSignals()
	initialIPs := []string{"192.0.2.1"}
	var pending []eximMutation
	oldDaemon := &eximServiceAdapter{EximAdapter: a, mutate: func(r eximMutation) error {
		pending = append(pending, r)
		return nil
	}}
	if err := oldDaemon.Apply(cfg, initialIPs); err != nil || len(pending) != 1 {
		t.Fatalf("old daemon: err=%v requests=%d", err, len(pending))
	}
	worker := func(r eximMutation) error {
		return handleEximMutation(strings.NewReader(mutationBody(t, r)), lockedEximAdapter{a}.mutate)
	}
	newDaemon := &eximServiceAdapter{EximAdapter: a, mutate: worker}
	if err := newDaemon.Apply(cfg, initialIPs); err != nil {
		t.Fatal(err)
	}
	if err := newDaemon.RefreshBadIPs([]string{"192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	err := worker(pending[0])
	if !errors.Is(err, errSuperseded) || WorkerExitCode(err) != workerBusyExit {
		t.Errorf("old worker: err=%v exit=%d, want superseded", err, WorkerExitCode(err))
	}
	if side.rebuilds != 1 {
		t.Errorf("rebuilds=%d, want only the new worker's rebuild", side.rebuilds)
	}
	data, err := os.ReadFile(a.badIPsPath)
	if err != nil || string(data) != "192.0.2.2: 1\n" {
		t.Errorf("old worker replaced refreshed lookup: %q, err=%v", data, err)
	}
}

// A writable lock does not imply that the request can be committed. Failure
// to replace its destination must preserve the guard and start no worker.
func TestEximServiceRequestWriteFailureStartsNoWorker(t *testing.T) {
	a, side := testAdapter(t)
	original := writeInstalledConf(t, a)
	if err := os.MkdirAll(a.requestPath(), 0o755); err != nil {
		t.Fatal(err)
	}
	calls := 0
	service := &eximServiceAdapter{EximAdapter: a, mutate: func(eximMutation) error { calls++; return nil }}
	for _, submit := range []func() error{func() error { return service.Apply(bothSignals(), nil) }, service.Remove} {
		if err := submit(); err == nil || errors.Is(err, eximlock.ErrBusy) {
			t.Errorf("recording failure=%v, want a non-busy error", err)
		}
	}
	data, err := os.ReadFile(a.localConf)
	if err != nil || string(data) != original || calls != 0 || side.rebuilds != 0 {
		t.Fatalf("guard changed: err=%v calls=%d rebuilds=%d conf=%q", err, calls, side.rebuilds, data)
	}
	if err := eximlock.With(filepath.Dir(a.badIPsPath), func() error { return nil }); err != nil {
		t.Fatalf("recording failure left lock held: %v", err)
	}
}

// An identified request cannot use the legacy missing-record allowance.
// Losing or failing to read its record must leave the installed guard alone.
func TestEximServiceWorkerRequiresItsRecordedRequest(t *testing.T) {
	for _, unreadable := range []bool{false, true} {
		t.Run(fmt.Sprintf("unreadable=%t", unreadable), func(t *testing.T) {
			a, side := testAdapter(t)
			original := writeInstalledConf(t, a)
			var pending []eximMutation
			service := &eximServiceAdapter{EximAdapter: a, mutate: func(r eximMutation) error {
				pending = append(pending, r)
				return nil
			}}
			if err := service.Remove(); err != nil || len(pending) != 1 {
				t.Fatalf("submit removal: err=%v requests=%d", err, len(pending))
			}
			if err := os.Rename(a.requestPath(), a.requestPath()+".saved"); err != nil {
				t.Fatal(err)
			}
			if unreadable {
				if err := os.Mkdir(a.requestPath(), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			err := handleEximMutation(strings.NewReader(mutationBody(t, pending[0])), lockedEximAdapter{a}.mutate)
			if err == nil || errors.Is(err, errSuperseded) == unreadable {
				t.Errorf("worker error=%v, want superseded only for a missing record", err)
			}
			data, readErr := os.ReadFile(a.localConf)
			if readErr != nil || string(data) != original || side.rebuilds != 0 {
				t.Fatalf("guard changed: err=%v rebuilds=%d conf=%q", readErr, side.rebuilds, data)
			}
		})
	}
}
