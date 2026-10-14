package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

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
		return eximlock.WithRetry(context.Background(), dir, eximlock.RecordWait, func() error {
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
// the lock for longer than eximlock.RecordWait. The record is written and
// flushed before the lock is taken; under the lock it is only renamed into
// place. The directory is flushed after unlocking, before reporting success.
func recordRequest(ctx context.Context, dir string, body []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// #nosec G301 -- the shared lock directory, created with the mode eximlock uses.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	path := filepath.Join(dir, RequestFile)
	tmp, err := stageRecord(path, body)
	if err != nil {
		return false, err
	}
	published := false
	err = eximlock.WithRetry(ctx, dir, eximlock.RecordWait, func() error {
		if renameErr := os.Rename(tmp, path); renameErr != nil {
			return renameErr
		}
		published = true
		return nil
	})
	if !published {
		_ = os.Remove(tmp)
	}
	if errors.Is(err, eximlock.ErrBusy) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	err = syncRecordDir(dir)
	return err == nil, err
}

// stageRecord writes body to a new 0600 temporary file next to path and
// flushes it. An interrupted write leaves the previous record in place.
// Tests replace it.
var stageRecord = func(path string, body []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	_, err = f.Write(body)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// A file flush alone does not persist the rename. Keep the directory flush
// outside the shared lock, too, so it cannot delay another record writer.
var syncRecordDir = func(dir string) error {
	// #nosec G304 -- fixed CSM state directory, opened only to persist the rename.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if closeErr := d.Close(); err == nil {
		err = closeErr
	}
	return err
}
