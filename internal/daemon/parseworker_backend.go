package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/parseworker"
	"github.com/pidginhost/csm/internal/workerproc"
)

// parseWorkerUnitPrefix starts every parse worker unit name, so leftovers of
// a daemon that died can be found and killed.
const parseWorkerUnitPrefix = "csm-parse-worker-"

// stopParseWorkerUnits is a seam for tests.
var stopParseWorkerUnits = workerproc.StopUnits

// checkParseWorkerCommand is a seam for tests whose binary path does not exist.
var checkParseWorkerCommand = workerproc.CheckUnitCommand

func (d *Daemon) initParseWorkers() error {
	if d.binaryPath == "" {
		return errors.New("parse worker: daemon binary unknown")
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[%s] parse-worker: "+format+"\n", append([]any{ts()}, args...)...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := stopParseWorkerUnits(ctx, parseWorkerUnitPrefix); err != nil {
		logf("stop leftover units: %v", err)
	}
	cancel()
	// Refused here, once, rather than at every launch: a unit's dynamic user
	// cannot run an owner-only binary, so each worker would fail at exec.
	if err := checkParseWorkerCommand(d.binaryPath); err != nil {
		return fmt.Errorf("parse worker: %w", err)
	}
	lister, err := parseworker.NewLister(parseworker.ListerConfig{
		Launch: workerproc.UnitLauncher(parseworker.UnitConfig(d.binaryPath, parseWorkerUnitPrefix+"zip0", logf)),
		Log:    logf,
	})
	if err != nil {
		return err
	}
	d.zipLister = lister
	d.registerQueueSource("archive_list", lister)
	checks.SetZipLister(lister)
	return nil
}

func (d *Daemon) stopParseWorkers() {
	checks.SetZipLister(nil)
	if d.zipLister == nil {
		return
	}
	_ = d.zipLister.Stop()
	d.zipLister = nil
}
