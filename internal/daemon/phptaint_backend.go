package daemon

import (
	"fmt"
	"os"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/phptaintworker"
)

// phpTaintWorkerTimeout is shorter than the check-side outer deadline. The
// supervisor must have time to kill and reap a stuck parser before the shared
// deep-content walk gives up on the request.
const phpTaintWorkerTimeout = 20 * time.Second

func (d *Daemon) initPHPTaintAnalyzer() error {
	sup, err := phptaintworker.NewSupervisor(phptaintworker.SupervisorConfig{
		Command: d.binaryPath,
		Args:    []string{"phptaint-worker"},
		Env:     os.Environ(),
		Timeout: phpTaintWorkerTimeout,
		Log: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "[%s] phptaint-worker: "+format+"\n", append([]any{ts()}, args...)...)
		},
	})
	if err != nil {
		return err
	}
	d.phpTaintSup = sup
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
