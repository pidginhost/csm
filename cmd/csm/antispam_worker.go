package main

import (
	"fmt"
	"io"
	"os"

	"github.com/pidginhost/csm/internal/antispam/txn"
	"github.com/pidginhost/csm/internal/antispam/worker"
	"github.com/pidginhost/csm/internal/eximlock"
)

func runAntispamWorker() {
	lock := func(mutate func() error) error { return eximlock.With(eximlock.Dir, mutate) }
	os.Exit(antispamWorker(os.Geteuid(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, txn.New(), lock))
}

// antispamWorker runs one antispam transaction for a root caller. Nothing
// reaches stdout until the transaction has ended, and child commands get
// their own pipes, so a caller that closed the result pipe can only stop
// the worker at that last write, after the record is on disk.
func antispamWorker(euid int, args []string, in io.Reader, out, errOut io.Writer, t worker.Transactor, lock worker.Locker) int {
	if euid != 0 || len(args) != 1 {
		_, _ = fmt.Fprintln(errOut, "antispam worker requires root and reads one request from stdin")
		return 1
	}
	return worker.Handle(in, out, t, lock)
}
