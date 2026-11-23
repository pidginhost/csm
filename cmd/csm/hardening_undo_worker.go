package main

import (
	"fmt"
	"io"
	"os"

	"github.com/pidginhost/csm/internal/checks"
)

func runHardeningUndoWorker() {
	os.Exit(hardeningUndoWorker(os.Geteuid(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, undoHardeningWithConfig))
}

// hardeningUndoWorker undoes one applied hardening fix for a root caller
// and writes the result to stdout. The daemon starts it outside its
// sandbox, as it does the apply worker.
func hardeningUndoWorker(euid int, args []string, in io.Reader, out, errOut io.Writer, undo func(string) checks.HardeningFixResult) int {
	if euid != 0 || !hardeningWorkerArgs(checks.HardeningUndoWorkerCommand, args) {
		_, _ = fmt.Fprintln(errOut, "hardening undo worker requires root and reads one request from stdin")
		return 1
	}
	if err := checks.HandleHardeningUndo(in, out, undo); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

// undoHardeningWithConfig loads the configuration as the apply worker does,
// so PHP drop-in paths are derived on the platform the apply saw.
func undoHardeningWithConfig(name string) checks.HardeningFixResult {
	if _, err := loadHardeningWorkerConfig(); err != nil {
		return checks.HardeningFixResult{Name: name, Title: name, Status: "failed", Message: err.Error()}
	}
	return checks.UndoHardening(name)
}
