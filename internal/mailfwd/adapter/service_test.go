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

func TestEximMutationPreservesTransaction(t *testing.T) {
	a, side := testAdapter(t)
	original := platform.EximLocalSkeleton + "# operator setting\n"
	if err := os.WriteFile(a.localConf, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	request := eximMutation{Operation: "apply", Config: policy.Config{Enabled: true, HoldSignals: policy.HoldSignals{BounceBackscatter: true}}, BadIPs: []string{"192.0.2.1"}}
	body := mutationBody(t, request)
	if err := handleEximMutation(strings.NewReader(body), a); err != nil {
		t.Fatal(err)
	}
	status, err := a.Status()
	if err != nil || !status.Installed || side.rebuilds != 1 {
		t.Fatalf("status=%+v error=%v rebuilds=%d", status, err, side.rebuilds)
	}
	if err = handleEximMutation(strings.NewReader(`{"operation":"remove"}`), a); err != nil {
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
	if err = handleEximMutation(strings.NewReader(body), a); !errors.Is(err, failure) {
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
		if err := handleEximMutation(strings.NewReader(input), a); err == nil {
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
	if !reflect.DeepEqual(got, []eximMutation{{Operation: "apply", Config: cfg, BadIPs: ips}, {Operation: "remove"}}) {
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

// With no rule installed, Remove starts no root worker, so a reload with the
// guard off never contends for the Exim lock.
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

// A rule Remove cannot prove absent still goes to the worker: an installed
// rule, half of one, or a file the daemon cannot read.
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
			if err := service.Remove(); !errors.Is(err, io.ErrClosedPipe) || !reflect.DeepEqual(got, []eximMutation{{Operation: "remove"}}) {
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
	busyErr := handleEximMutation(strings.NewReader(`{"operation":"remove"}`), lockedEximAdapter{a})
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if code := WorkerExitCode(busyErr); code != workerBusyExit || side.rebuilds != 0 {
		t.Fatalf("exit=%d err=%v rebuilds=%d", code, busyErr, side.rebuilds)
	}
	if code := WorkerExitCode(handleEximMutation(strings.NewReader(`{"operation":"remove"}`), lockedEximAdapter{a})); code != 0 || side.rebuilds != 1 {
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
