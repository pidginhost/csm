package worker

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/eximlock"
)

// RequestFile holds the latest request the daemon handed to the worker. It
// sits next to the shared lock and changes only under it.
const RequestFile = "antispam-request.json"

// requestDir holds the lock and the request record for Run. Tests point it
// at a temporary directory.
var requestDir = eximlock.Dir

// errSuperseded reports a request the daemon replaced before this worker
// reached the lock, for example one from before a daemon restart. The newer
// request decides, so the worker reports busy and changes nothing.
var errSuperseded = errors.New("a newer antispam request replaced this one")

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
// the lock.
func recordRequest(dir string, body []byte) (bool, error) {
	err := eximlock.With(dir, func() error {
		return os.WriteFile(filepath.Join(dir, RequestFile), body, 0o600)
	})
	if errors.Is(err, eximlock.ErrBusy) {
		return false, nil
	}
	return err == nil, err
}
