package webserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// recordingRunner records every argv and fails the ones failOn matches.
type recordingRunner struct {
	calls  [][]string
	failOn func(argv []string) bool
	output string
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	argv := append([]string{name}, args...)
	r.calls = append(r.calls, argv)
	if r.failOn != nil && r.failOn(argv) {
		return []byte(r.output), errors.New("exit status 1")
	}
	return nil, nil
}

func isNginxConfigtest(argv []string) bool {
	return len(argv) >= 2 && slices.Equal(argv[len(argv)-2:], []string{"nginx", "-t"})
}

// nginx -t opens its log files for writing, which the
// daemon's read-only service sandbox refuses.
func TestNginxValidateRunsConfigtestOutsideServiceSandbox(t *testing.T) {
	r := &recordingRunner{}
	h := newNginxHandler(r)
	h.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }

	if err := h.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	want := [][]string{
		{"/usr/bin/systemd-run", "--quiet", "--collect", "--pipe", "--property=RuntimeMaxSec=15s", "--", "/bin/true"},
		{"/usr/bin/systemd-run", "--quiet", "--collect", "--pipe", "--property=RuntimeMaxSec=15s", "--", "nginx", "-t"},
	}
	if !slices.EqualFunc(r.calls, want, slices.Equal[[]string]) {
		t.Fatalf("calls = %v, want %v", r.calls, want)
	}
}

func TestNginxValidateRunsDirectlyWithoutSystemdRun(t *testing.T) {
	r := &recordingRunner{}
	h := newNginxHandler(r)
	h.lookPath = func(string) (string, error) { return "", errors.New("not found") }

	if err := h.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(r.calls) != 1 || !slices.Equal(r.calls[0], []string{"nginx", "-t"}) {
		t.Fatalf("calls = %v, want one direct nginx -t", r.calls)
	}
}

func TestNginxValidateReportsConfigtestOutput(t *testing.T) {
	r := &recordingRunner{failOn: isNginxConfigtest, output: "nginx: [emerg] unknown directive"}
	h := newNginxHandler(r)
	h.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }

	err := h.Validate()
	if err == nil {
		t.Fatal("Validate passed a failing configtest")
	}
	if !strings.Contains(err.Error(), "nginx configtest failed") || !strings.Contains(err.Error(), "unknown directive") {
		t.Fatalf("error lost the configtest output: %v", err)
	}
	if len(r.calls) != 2 || r.calls[1][0] != "/usr/bin/systemd-run" {
		t.Fatalf("calls = %v, want a probe and one wrapped configtest without retry", r.calls)
	}
}

type nginxRunnerFunc func(context.Context, string, ...string) ([]byte, error)

func (f nginxRunnerFunc) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f(ctx, name, args...)
}

func TestNginxValidatePreservesConfigtestBudgetAfterProbe(t *testing.T) {
	for _, probe := range []string{"success", "failure", "timeout"} {
		t.Run(probe, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls [][]string
				r := nginxRunnerFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
					argv := append([]string{name}, args...)
					calls = append(calls, argv)
					if !isNginxConfigtest(argv) {
						if probe == "timeout" {
							<-ctx.Done()
							return nil, ctx.Err()
						}
						time.Sleep(2 * time.Second)
						if probe == "failure" {
							return nil, errors.New("bus unavailable")
						}
						return nil, nil
					}
					select {
					case <-time.After(14 * time.Second):
						return nil, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				})
				h := newNginxHandler(r)
				h.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }

				if err := h.Validate(); err != nil {
					t.Fatalf("probe consumed the configtest budget: %v", err)
				}
				wantCommand := "nginx"
				if probe == "success" {
					wantCommand = "/usr/bin/systemd-run"
				}
				if len(calls) != 2 || calls[1][0] != wantCommand || !isNginxConfigtest(calls[1]) {
					t.Fatalf("calls = %v, want one probe followed by one configtest via %s", calls, wantCommand)
				}
			})
		})
	}
}

func TestNginxValidateBoundsConfigtestWait(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrapped=%t", wrapped), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var tests int
				r := nginxRunnerFunc(func(ctx context.Context, name string, args ...string) ([]byte, error) {
					if !isNginxConfigtest(append([]string{name}, args...)) {
						return nil, nil
					}
					tests++
					<-ctx.Done()
					return nil, ctx.Err()
				})
				h := newNginxHandler(r)
				h.lookPath = func(file string) (string, error) {
					if !wrapped {
						return "", errors.New("not found")
					}
					return "/usr/bin/" + file, nil
				}
				start := time.Now()
				err := h.Validate()
				if err == nil || !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
					t.Fatalf("Validate = %v, want configtest deadline failure", err)
				}
				if elapsed := time.Since(start); elapsed != 15*time.Second || tests != 1 {
					t.Fatalf("elapsed = %s, configtests = %d, want one test bounded to 15s", elapsed, tests)
				}
			})
		})
	}
}
