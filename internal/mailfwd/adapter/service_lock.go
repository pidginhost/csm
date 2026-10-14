package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/eximlock"
)

// errSuperseded reports a request the daemon replaced before this worker
// reached the lock. The newer request decides, so it is not a failure.
var errSuperseded = errors.New("a newer forward-guard request replaced this one")

// requestFile holds the latest request the daemon handed to the worker. It
// sits next to the shared lock and changes only under it.
const requestFile = "request.json"

// lockedEximAdapter runs one worker transaction under the shared Exim lock,
// and only while its request is still the latest one the daemon recorded.
type lockedEximAdapter struct{ *EximAdapter }

func (a lockedEximAdapter) mutate(request eximMutation) error {
	return eximlock.WithRetry(context.Background(), filepath.Dir(a.badIPsPath), eximlock.RecordWait, func() error {
		latest, err := a.isLatest(request)
		if err != nil {
			return err
		}
		if !latest {
			return errSuperseded
		}
		return request.applyTo(a.EximAdapter)
	})
}

func (a *EximAdapter) requestPath() string {
	return filepath.Join(filepath.Dir(a.badIPsPath), requestFile)
}

// isLatest reports whether request is the one the daemon recorded last. The
// daemon records the same encoding it sends, including the submission ID.
// Only a request without an ID can predate request recording.
func (a *EximAdapter) isLatest(request eximMutation) (bool, error) {
	recorded, err := os.ReadFile(a.requestPath()) // #nosec G304 -- fixed CSM state path next to the lock
	if errors.Is(err, os.ErrNotExist) {
		return request.RequestID == "", nil
	}
	if err != nil {
		return false, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return false, err
	}
	return bytes.Equal(recorded, body), nil
}
