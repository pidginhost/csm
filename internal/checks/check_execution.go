package checks

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/obs"
)

type checkExecutionOutcome struct {
	findings []alert.Finding
	panicErr string
}

func executeCheckAsync(ctx context.Context, component string, fn func() []alert.Finding) *checkExecution {
	return checkExecutions.execute(ctx, component, fn)
}

func (e *checkExecution) run(component string, fn func() []alert.Finding) {
	e.monitor.mu.Lock()
	e.started = time.Now()
	e.monitor.mu.Unlock()
	defer e.release()
	outcome := checkExecutionOutcome{}
	completed := false
	defer func() {
		if !completed {
			e.fail()
		}
		if recovered := recover(); recovered != nil {
			panicValue := fmt.Sprint(recovered)
			outcome.panicErr = fmt.Sprintf("%s\n%s", panicValue, debug.Stack())
			obs.CaptureMsg(component, "security check panic: "+panicValue)
		}
		e.done <- outcome
	}()
	outcome.findings = fn()
	completed = true
}
