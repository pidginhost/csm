package webserver

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
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
	tests := 0
	for _, argv := range r.calls {
		if !isNginxConfigtest(argv) {
			continue
		}
		tests++
		if argv[0] != "/usr/bin/systemd-run" {
			t.Errorf("configtest ran inside the sandbox: %v", argv)
		}
		if !slices.Contains(argv, "--pipe") {
			t.Errorf("configtest output is not captured: %v", argv)
		}
	}
	if tests != 1 {
		t.Fatalf("configtest ran %d times, want 1: %v", tests, r.calls)
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
}
