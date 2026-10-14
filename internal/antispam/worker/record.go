package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/atomicio"
	"github.com/pidginhost/csm/internal/eximlock"
)

// RequestFile holds the latest request, or null when reconciliation has
// invalidated pending workers. It changes only under the shared lock.
const RequestFile = "antispam-request.json"

// requestDir holds the lock and the request record for Run. Tests point it
// at a temporary directory.
var requestDir = eximlock.Dir

// errSuperseded reports a request the daemon replaced before this worker
// reached the lock, for example one from before a daemon restart. The newer
// request decides, so the worker reports busy and changes nothing.
var errSuperseded = errors.New("a newer antispam request replaced this one")

// Invalidate stops pending workers before reconcile reads the host. Even a
// pass that needs no worker must supersede requests from an older daemon.
// An active transaction holds the lock, so the caller retries after it ends.
func Invalidate(ctx context.Context) error {
	recorded, err := recordRequest(ctx, requestDir, []byte("null"))
	if err != nil {
		return err
	}
	if !recorded {
		return eximlock.ErrBusy
	}
	return nil
}

// Lock is the worker's Locker: it holds the shared lock in dir and runs
// mutate only while request is the latest one recorded there. A missing
// record comes from a daemon that predates it, so the request runs.
func Lock(dir string) Locker {
	return func(request []byte, mutate func() error) error {
		return eximlock.With(dir, func() error {
			// #nosec G304 -- fixed CSM state path next to the lock.
			recorded, err := os.ReadFile(filepath.Join(dir, RequestFile))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err == nil && !bytes.Equal(recorded, request) {
				return errSuperseded
			}
			return mutate()
		})
	}
}

// recordRequest records body as the latest request under the shared lock in
// dir. It reports false without an error while another transaction holds
// the lock for longer than eximlock.RecordWait.
func recordRequest(ctx context.Context, dir string, body []byte) (bool, error) {
	err := eximlock.WithRetry(ctx, dir, eximlock.RecordWait, func() error {
		return atomicio.AtomicWrite(filepath.Join(dir, RequestFile), 0o600, body)
	})
	if errors.Is(err, eximlock.ErrBusy) {
		return false, nil
	}
	return err == nil, err
}
