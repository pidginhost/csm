package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/parseworker"
	"github.com/pidginhost/csm/internal/workerproc"
)

// parseWorkerUnitPrefix starts every parse worker unit name, so leftovers of
// a daemon that died can be found and killed.
const parseWorkerUnitPrefix = "csm-parse-worker-"

// parseWorkerMemoryLimit caps a parse worker's memory and swap together.
const parseWorkerMemoryLimit = 512 << 20

// stopParseWorkerUnits is a seam for tests.
var stopParseWorkerUnits = workerproc.StopUnits

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
	lister, err := parseworker.NewLister(parseworker.ListerConfig{
		Launch: workerproc.UnitLauncher(workerproc.UnitConfig{
			Prefix:        parseWorkerUnitPrefix + "zip0",
			Command:       d.binaryPath,
			Args:          []string{"parse-worker", "--memory-limit=" + strconv.Itoa(parseWorkerMemoryLimit)},
			MemoryLimit:   parseWorkerMemoryLimit,
			FileSizeLimit: 64 << 20,
			RuntimeMax:    time.Hour,
			StartTimeout:  10 * time.Second,
			Protocol:      parseworker.ProtocolVersion,
			Limits:        parseworker.Limits,
			Log:           logf,
		}),
		Log: logf,
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
