package maillog

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Supervise retries source selection and attachment until ctx is canceled or
// consume returns false. status receives nil only after successful attachment,
// and an error while unavailable. Each old reader finishes before its replacement
// starts, so source migration cannot count the same event through two readers.
func Supervise(ctx context.Context, factory func() (Reader, error), status func(error), consume func(Line) bool) {
	delay := time.Second
	var statusMu sync.Mutex
	reported, failed := false, false
	lastFailure := ""
	report := func(err error) {
		// File disappearance must change health even while consume is blocked.
		// Serialize that callback with attachment and retry status updates.
		statusMu.Lock()
		defer statusMu.Unlock()
		failure := ""
		if err != nil {
			failure = err.Error()
		}
		if reported && failed == (err != nil) && lastFailure == failure {
			return
		}
		reported, failed, lastFailure = true, err != nil, failure
		status(err)
	}
	ready := func() {
		delay = time.Second
		report(nil)
	}
	for ctx.Err() == nil {
		reader, err := factory()
		if err == nil {
			err = consumeReader(ctx, reader, ready, report, consume)
		}
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return
		}
		report(err)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(delay*2, 30*time.Second)
	}
}

func consumeReader(ctx context.Context, reader Reader, ready func(), unavailable func(error), consume func(Line) bool) error {
	readerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	gone := make(chan error, 1)
	if file, ok := reader.(*FileReader); ok {
		file.SetOnGone(func(err error) {
			unavailable(err)
			select {
			case gone <- err:
			default:
			}
		})
	}
	lines, err := reader.Run(readerCtx)
	if err != nil {
		return err
	}
	defer func() {
		cancel()
		for line := range lines {
			line.reject()
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	ready()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-gone:
			cancel()
			for line := range lines {
				if ctxErr := ctx.Err(); ctxErr != nil {
					line.reject()
					return ctxErr
				}
				if !line.Process(consume) {
					return context.Canceled
				}
			}
			return err
		case line, ok := <-lines:
			if !ok {
				return errors.New("mail log reader stopped")
			}
			if !line.Process(consume) {
				return context.Canceled
			}
		}
	}
}
