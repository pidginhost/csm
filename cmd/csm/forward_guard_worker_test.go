package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/eximlock"
)

func TestForwardGuardWorkerRefusesBeforeReading(t *testing.T) {
	for name, tc := range map[string]struct {
		euid int
		args []string
	}{
		"not root":       {1000, []string{"forward-guard-worker"}},
		"no command":     {0, nil},
		"extra argument": {0, []string{"forward-guard-worker", "--force"}},
	} {
		t.Run(name, func(t *testing.T) {
			var errOut bytes.Buffer
			calls := 0
			code := forwardGuardWorker(tc.euid, tc.args, strings.NewReader(`{"operation":"remove"}`), &errOut, func(io.Reader) error { calls++; return nil })
			if code != 1 || calls != 0 || !strings.Contains(errOut.String(), "requires root") {
				t.Errorf("code=%d calls=%d err=%q", code, calls, errOut.String())
			}
		})
	}
}

// Exit status 75 is the busy signal the daemon reads back through
// systemd-run or a direct run; every other failure exits 1.
func TestForwardGuardWorkerExitStatus(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"done":   {nil, 0},
		"busy":   {fmt.Errorf("%w: resource temporarily unavailable", eximlock.ErrBusy), 75},
		"failed": {errors.New("buildeximconf failed"), 1},
	} {
		t.Run(name, func(t *testing.T) {
			var errOut bytes.Buffer
			code := forwardGuardWorker(0, []string{"forward-guard-worker"}, strings.NewReader(`{"operation":"remove"}`), &errOut, func(io.Reader) error { return tc.err })
			if code != tc.want || (tc.err != nil) != strings.Contains(errOut.String(), fmt.Sprint(tc.err)) {
				t.Errorf("code=%d err=%q", code, errOut.String())
			}
		})
	}
}
