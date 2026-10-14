package main

import (
	"fmt"
	"io"
	"os"

	"github.com/pidginhost/csm/internal/mailfwd/adapter"
)

func runForwardGuardWorker() {
	os.Exit(forwardGuardWorker(os.Geteuid(), os.Args[1:], os.Stdin, os.Stderr, adapter.HandleEximMutation))
}

// forwardGuardWorker runs one forward-guard request for a root caller. Its
// exit status tells the daemon a busy Exim lock apart from a failed change.
func forwardGuardWorker(euid int, args []string, in io.Reader, errOut io.Writer, handle func(io.Reader) error) int {
	if euid != 0 || len(args) != 1 {
		_, _ = fmt.Fprintln(errOut, "forward-guard worker requires root and reads one request from stdin")
		return 1
	}
	err := handle(in)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
	}
	return adapter.WorkerExitCode(err)
}
