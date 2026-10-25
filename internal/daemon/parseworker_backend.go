package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	emime "github.com/pidginhost/csm/internal/mime"
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

// parseWorkerLauncher is a seam for tests that must not start units.
var parseWorkerLauncher = workerproc.UnitLauncher

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
		d.reportIsolationUnavailable(err)
		return fmt.Errorf("parse worker: %w", err)
	}
	registerParseWorkerMetrics()
	launchZip := countParseWorkerStarts("zip", parseWorkerLauncher(parseworker.UnitConfig(d.binaryPath, parseWorkerUnitPrefix+"zip0", 64<<20, logf)))
	lister, err := parseworker.NewLister(parseworker.ListerConfig{
		Launch: func(ctx context.Context) (workerproc.Process, error) {
			proc, err := launchZip(ctx)
			// Descriptor exhaustion bypasses the failure hook and breaker,
			// but still leaves archives without an isolated parser.
			if err != nil && ctx.Err() == nil {
				d.reportIsolationUnavailable(err)
			}
			return proc, err
		},
		Log:   logf,
		OnJob: func(outcome string, memory uint64) { recordParseJob("zip", outcome, memory) },
	})
	if err != nil {
		return err
	}
	d.zipLister = lister
	d.registerQueueSource("archive_list", lister)
	checks.SetZipLister(lister)
	if d.cfg == nil || !d.cfg.EmailAV.Enabled {
		return nil
	}
	// The spool watcher runs one scan goroutine per slot, sized the same way.
	extractor, err := parseworker.NewExtractor(parseworker.ExtractorConfig{
		Size: d.cfg.EmailAV.ScanConcurrency,
		Launch: func(slot int) workerproc.Launcher {
			name := fmt.Sprintf("%smail%d", parseWorkerUnitPrefix, slot)
			return countParseWorkerStarts("mail", parseWorkerLauncher(parseworker.UnitConfig(d.binaryPath, name, parseworker.FileSizeLimit(d.cfg.EmailAV.MaxAttachmentSize), logf)))
		},
		Log:   logf,
		OnJob: func(outcome string, memory uint64) { recordParseJob("mail", outcome, memory) },
	})
	if err != nil {
		return err
	}
	d.mailExtractor = extractor
	d.registerQueueSource("email_extract", extractor)
	return nil
}

// reportIsolationUnavailable raises email_av_isolation_unavailable for parse
// workers that cannot run. It shares the spool watcher's hourly allowance.
func (d *Daemon) reportIsolationUnavailable(err error) {
	d.parseFindings.emit(d.alertCh, "email_av_isolation_unavailable", alert.Critical, isolationAlertInterval,
		fmt.Sprintf("Parse worker units cannot run: %v. Email attachments are handled as incomplete scans under email_av.fail_mode, and phishing-kit zips are reported as not checked.", err))
}

// mailExtractor is what the spool watcher needs from the mail parse workers;
// tests fake it.
type mailExtractor interface {
	Size() int
	Extract(ctx context.Context, slot int, header, body *os.File, limits emime.Limits) (*emime.ExtractionResult, error)
}

// spoolExtractor is the mail extractor for a new spool watcher, or nil.
// A nil pointer must not become a non-nil interface.
func (d *Daemon) spoolExtractor() mailExtractor {
	// Panic cleanup can clear the extractor while a watcher is restarting.
	d.spoolWatcherMu.Lock()
	defer d.spoolWatcherMu.Unlock()
	if d.mailExtractor == nil {
		return nil
	}
	return d.mailExtractor
}

func (d *Daemon) stopParseWorkers() {
	// During shutdown a watcher may still be draining or finishing a
	// restart, and must keep its pool until it returns. Before shutdown is
	// signalled (a panic unwinding Run) nothing tells those goroutines to
	// stop: waiting would hang the daemon instead of letting it crash and be
	// restarted.
	select {
	case <-d.stopCh:
		d.wg.Wait()
	default:
	}
	checks.SetZipLister(nil)
	d.spoolWatcherMu.Lock()
	extractor := d.mailExtractor
	d.mailExtractor = nil
	d.spoolWatcherMu.Unlock()
	if extractor != nil {
		_ = extractor.Stop()
	}
	if d.zipLister == nil {
		return
	}
	_ = d.zipLister.Stop()
	d.zipLister = nil
}
