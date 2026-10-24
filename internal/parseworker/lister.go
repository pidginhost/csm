package parseworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/queuehealth"
	"github.com/pidginhost/csm/internal/workerproc"
)

// errIncomplete wraps a worker's report that it could not list the whole
// zip. The zip is to blame, not the worker.
var errIncomplete = errors.New("zip listing incomplete")

// ListerConfig configures a Lister.
type ListerConfig struct {
	Launch workerproc.Launcher
	Log    func(string, ...any)
}

// Lister lists tenant zips through one parse worker at a time.
type Lister struct {
	proc *workerproc.Supervisor
}

// NewLister starts no worker; the first ListZip does.
func NewLister(cfg ListerConfig) (*Lister, error) {
	proc, err := workerproc.New(workerproc.Config{
		Name:        "parse worker (zip)",
		Launch:      cfg.Launch,
		Timeout:     30 * time.Second,
		Limits:      Limits,
		Log:         cfg.Log,
		MaxJobs:     1000,
		IdleTimeout: 10 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	return &Lister{proc: proc}, nil
}

// ListZip sends zip to the worker and calls visit with each entry, in
// directory order. The worker's listing is checked in full before visit
// sees any of it; a listing that fails the check kills the worker and the
// error matches workerproc.ErrWorkerFailed. A zip the worker could not list
// completely is an error that is not a worker failure. visit's error comes
// back unwrapped.
func (l *Lister) ListZip(ctx context.Context, zip *os.File, size int64, maxDirBytes uint64, visit func(name string, dir bool) error) error {
	payload, err := json.Marshal(ListZipArgs{MaxDirBytes: maxDirBytes})
	if err != nil {
		return err
	}
	var res ListZipResult
	var listingSize int64
	_, fds, err := l.proc.Call(ctx, workerproc.Frame{Op: OpListZip, Payload: payload}, []*os.File{zip},
		func(reply workerproc.Frame, fds []*os.File) (bool, error) {
			var wire struct {
				Entries    *uint64 `json:"entries"`
				Incomplete string  `json:"incomplete,omitempty"`
			}
			dec := json.NewDecoder(bytes.NewReader(reply.Payload))
			dec.DisallowUnknownFields()
			if decodeErr := dec.Decode(&wire); decodeErr != nil {
				return false, fmt.Errorf("list_zip reply: %w", decodeErr)
			}
			if wire.Entries == nil {
				return false, errors.New("list_zip reply has no entry count")
			}
			res = ListZipResult{Entries: *wire.Entries, Incomplete: wire.Incomplete}
			if res.Incomplete != "" {
				if len(fds) != 0 || res.Entries != 0 || len(res.Incomplete) > maxIncomplete {
					return false, errors.New("malformed incomplete listing")
				}
				return false, nil
			}
			var checkErr error
			listingSize, checkErr = checkListing(ctx, fds, size, maxDirBytes, res.Entries)
			return false, checkErr
		})
	if err != nil {
		return err
	}
	if res.Incomplete != "" {
		return fmt.Errorf("%w: %s", errIncomplete, res.Incomplete)
	}
	defer func() { _ = fds[0].Close() }()
	_, err = readEntries(ctx, io.NewSectionReader(fds[0], 0, listingSize), maxDirBytes, visit)
	return err
}

// checkListing validates the worker's listing before anything trusts it: one
// immutable regular file, no larger than the zip (a record is 3 bytes plus
// the name, a central-directory record at least 46 plus the name), whole
// records only, exactly as many as the reply claims.
func checkListing(ctx context.Context, fds []*os.File, zipSize int64, maxDirBytes, entries uint64) (int64, error) {
	if len(fds) != 1 {
		return 0, fmt.Errorf("listing carries %d descriptors, want 1", len(fds))
	}
	// Seal checks precede even Stat: the size and every record must stay
	// unchanged from validation through delivery to visit.
	if err := checkSealed(fds[0]); err != nil {
		return 0, err
	}
	st, err := fds[0].Stat()
	if err != nil {
		return 0, err
	}
	if !st.Mode().IsRegular() {
		return 0, errors.New("listing is not a regular file")
	}
	if st.Size() > zipSize {
		return 0, fmt.Errorf("listing of %d bytes exceeds the %d-byte zip", st.Size(), zipSize)
	}
	n, err := readEntries(ctx, io.NewSectionReader(fds[0], 0, st.Size()), maxDirBytes, func(string, bool) error { return nil })
	if err != nil {
		return 0, fmt.Errorf("listing: %w", err)
	}
	if n != entries {
		return 0, fmt.Errorf("listing holds %d records, reply claims %d", n, entries)
	}
	return st.Size(), nil
}

// Stop kills the worker and refuses later listings.
func (l *Lister) Stop() error { return l.proc.Stop() }

// Stats reports the worker's spawn and breaker state.
func (l *Lister) Stats() workerproc.Stats { return l.proc.Stats() }

// QueueStatuses publishes the requests row.
func (l *Lister) QueueStatuses(now time.Time) map[string]queuehealth.Status {
	return l.proc.QueueStatuses(now)
}
