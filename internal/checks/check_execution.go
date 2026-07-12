package checks

import (
	"fmt"
	"runtime/debug"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/obs"
)

type checkExecutionOutcome struct {
	findings []alert.Finding
	panicErr string
}

func executeCheckAsync(component string, fn func() []alert.Finding) <-chan checkExecutionOutcome {
	done := make(chan checkExecutionOutcome, 1)
	go func() {
		outcome := checkExecutionOutcome{}
		defer func() {
			if recovered := recover(); recovered != nil {
				panicValue := fmt.Sprint(recovered)
				outcome.panicErr = fmt.Sprintf("%s\n%s", panicValue, debug.Stack())
				obs.CaptureMsg(component, "security check panic: "+panicValue)
			}
			done <- outcome
		}()
		outcome.findings = fn()
	}()
	return done
}
