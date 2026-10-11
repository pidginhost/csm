// Package worker runs CSM's antispam transactions at the root boundary and
// launches them from the daemon: one JSON request in, one JSON result out,
// under the shared Exim mutation lock.
package worker

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/pidginhost/csm/internal/antispam"
	"github.com/pidginhost/csm/internal/eximlock"
)

// Transactor performs the apply and remove transactions (spec sections 6.3
// and 6.4). Handle calls it only with a validated request, under the lock.
type Transactor interface {
	Apply(antispam.Settings) antispam.Result
	Remove() antispam.Result
}

// Locker runs mutate under the shared Exim mutation lock.
type Locker func(mutate func() error) error

// Handle reads one request from input, runs it under lock and writes one
// JSON result line to output. It returns the process exit code: 0 when the
// result is OK, 1 otherwise.
func Handle(input io.Reader, output io.Writer, t Transactor, lock Locker) int {
	result := handle(input, t, lock)
	line, err := json.Marshal(result)
	if err != nil {
		return 1
	}
	line = append(line, '\n')
	if n, err := output.Write(line); err != nil || n != len(line) || !result.OK {
		return 1
	}
	return 0
}

func handle(input io.Reader, t Transactor, lock Locker) antispam.Result {
	data, err := io.ReadAll(io.LimitReader(input, antispam.MaxRequestBytes+1))
	if err != nil {
		return antispam.Result{FailedStep: "request", Rollback: antispam.RollbackNone, Error: "cannot read request"}
	}
	req, settings, err := antispam.DecodeRequest(data)
	if err != nil {
		return antispam.Result{FailedStep: "request", Rollback: antispam.RollbackNone, Error: err.Error()}
	}
	var result antispam.Result
	err = lock(func() error {
		if req.Operation == antispam.OpApply {
			result = t.Apply(settings)
		} else {
			result = t.Remove()
		}
		return nil
	})
	if err != nil {
		result = antispam.Result{Busy: errors.Is(err, eximlock.ErrBusy), FailedStep: "lock", Rollback: antispam.RollbackNone, Error: err.Error()}
	}
	result.Operation = req.Operation
	return result
}
