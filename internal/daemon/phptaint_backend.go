package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/phptaintworker"
	"github.com/pidginhost/csm/internal/workerproc"
)

// phpTaintWorkerTimeout is shorter than the check-side outer deadline. The
// supervisor must have time to kill and reap a stuck parser before the shared
// deep-content walk gives up on the request.
const phpTaintWorkerTimeout = 20 * time.Second

// phpTaintWorkerUnitPrefix names the PHP taint worker units. Startup kills
// any left by a daemon that died, matching on the prefix plus "-".
const phpTaintWorkerUnitPrefix = "csm-phptaint-worker"

// phpTaintWorkerLauncher is a seam for tests that must not start units.
var phpTaintWorkerLauncher = workerproc.UnitLauncher

func (d *Daemon) initPHPTaintAnalyzer() error {
	if d.binaryPath == "" {
		return errors.New("phptaint worker: daemon binary unknown")
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[%s] phptaint-worker: "+format+"\n", append([]any{ts()}, args...)...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := stopParseWorkerUnits(ctx, phpTaintWorkerUnitPrefix+"-"); err != nil {
		logf("stop leftover units: %v", err)
	}
	cancel()
	// A unit's dynamic user cannot run an owner-only binary; refuse once here
	// rather than fail every analysis at exec.
	if err := checkParseWorkerCommand(d.binaryPath); err != nil {
		return fmt.Errorf("phptaint worker: %w", err)
	}
	unit := phptaintworker.UnitConfig(d.binaryPath, phpTaintWorkerUnitPrefix, logf)
	unit.InaccessiblePaths = parseWorkerHiddenPaths()
	sup, err := phptaintworker.NewSupervisor(phptaintworker.SupervisorConfig{
		Launch:  phpTaintWorkerLauncher(unit),
		Timeout: phpTaintWorkerTimeout,
		Log:     logf,
	})
	if err != nil {
		return err
	}
	d.phpTaintSup = sup
	d.registerQueueSource("php_taint", sup)
	checks.SetPHPTaintAnalyzer(sup)
	return nil
}

func (d *Daemon) stopPHPTaintAnalyzer() {
	checks.SetPHPTaintAnalyzer(nil)
	if d.phpTaintSup == nil {
		return
	}
	_ = d.phpTaintSup.Stop()
	d.phpTaintSup = nil
}
