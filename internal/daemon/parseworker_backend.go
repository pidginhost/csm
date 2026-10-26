package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/crashsample"
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

// parseWorkerHiddenPaths is a seam for tests: the account home volumes
// ProtectHome does not hide from workers.
var parseWorkerHiddenPaths = checks.AccountHomeVolumes

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
	hidden := parseWorkerHiddenPaths()
	unitConfig := func(name string, memoryLimit, fileSizeLimit uint64) workerproc.UnitConfig {
		cfg := parseworker.UnitConfig(d.binaryPath, name, memoryLimit, fileSizeLimit, logf)
		cfg.InaccessiblePaths = hidden
		return cfg
	}
	launchZip := countParseWorkerStarts("zip", parseWorkerLauncher(unitConfig(parseWorkerUnitPrefix+"zip0", parseworker.DefaultMemoryLimit, 64<<20)))
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
			return countParseWorkerStarts("mail", parseWorkerLauncher(unitConfig(name, mailWorkerMemoryLimit(d.cfg), parseworker.FileSizeLimit(d.cfg.EmailAV.MaxAttachmentSize))))
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

// mailWorkerMemoryLimit is the configured memory cap of each mail parse
// worker; validation keeps it at or above the minimum.
func mailWorkerMemoryLimit(cfg *config.Config) uint64 {
	if cfg.EmailAV.WorkerMemoryLimit < config.MinWorkerMemoryLimit {
		return parseworker.DefaultMemoryLimit
	}
	return uint64(cfg.EmailAV.WorkerMemoryLimit)
}

// reportIsolationUnavailable raises email_av_isolation_unavailable for parse
// workers that cannot run. It shares the spool watcher's hourly allowance.
func (d *Daemon) reportIsolationUnavailable(err error) {
	d.parseFindings.emit(d.alertCh, "email_av_isolation_unavailable", alert.Critical, isolationAlertInterval,
		fmt.Sprintf("Parse worker units cannot run: %q. Email attachments are handled as incomplete scans under email_av.fail_mode, and phishing-kit zips are reported as not checked.", err))
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

// initCrashSamples sets up the parse crash sample store. Phishing zips are
// kept only when email_av.keep_crash_samples is on.
func (d *Daemon) initCrashSamples() {
	if d.cfg == nil || d.cfg.StatePath == "" {
		return
	}
	d.crashSamples = crashsample.New(filepath.Join(d.cfg.StatePath, "parse-crashes"))
	checks.SetCrashSamples(d.keptCrashSamples())
}

// keptCrashSamples is the store new crash samples go to, or nil when
// email_av.keep_crash_samples is off.
func (d *Daemon) keptCrashSamples() *crashsample.Store {
	if d.crashSamples == nil || d.cfg == nil || !d.cfg.EmailAV.KeepCrashSamples {
		return nil
	}
	return d.crashSamples
}

// crashSampleSweep removes expired crash samples at start and then hourly.
// It runs whether or not samples are kept, so turning the setting off never
// leaves customer data behind.
func (d *Daemon) crashSampleSweep() {
	defer d.wg.Done()
	d.sweepCrashSamples()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.sweepCrashSamples()
		}
	}
}

func (d *Daemon) sweepCrashSamples() {
	if d.crashSamples == nil {
		return
	}
	n, err := d.crashSamples.Sweep()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] parse crash samples: sweep: %v\n", ts(), err)
	} else if n > 0 {
		fmt.Fprintf(os.Stderr, "[%s] parse crash samples: removed %d expired\n", ts(), n)
	}
}
