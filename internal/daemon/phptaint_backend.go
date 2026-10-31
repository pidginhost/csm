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
	unit := phptaintworker.UnitConfig(d.binaryPath, phpTaintWorkerUnitPrefix, logf)
	unit.InaccessiblePaths = parseWorkerHiddenPaths()
	launch := phpTaintWorkerLauncher(unit)
	sup, err := phptaintworker.NewSupervisor(phptaintworker.SupervisorConfig{
		Launch: func(ctx context.Context) (workerproc.Process, error) {
			// Keep preflight failures inside the supervisor: an absent analyzer
			// disables dispatch and would hide these files' coverage gaps.
			if err := checkParseWorkerCommand(unit.Command); err != nil {
				return nil, fmt.Errorf("phptaint worker: %w", err)
			}
			return launch(ctx)
		},
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
