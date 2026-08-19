package checks

import (
	"context"
	"sync"

	"github.com/pidginhost/csm/internal/phptaint"
)

// phpTaintWorker is the isolated analyzer this adapter routes through. It is
// nil until the daemon supervises one.
var (
	phpTaintWorkerMu sync.RWMutex
	phpTaintWorker   PHPTaintAnalyzer
)

// PHPTaintAnalyzer is what the daemon supplies: an analyzer that runs in a
// process the caller can kill.
type PHPTaintAnalyzer interface {
	Analyze(ctx context.Context, src []byte) phptaint.Report
}

// SetPHPTaintAnalyzer installs the supervised worker. Passing nil removes it,
// after which every candidate is reported as an unexamined coverage gap rather
// than analyzed in this process.
func SetPHPTaintAnalyzer(a PHPTaintAnalyzer) {
	phpTaintWorkerMu.Lock()
	defer phpTaintWorkerMu.Unlock()
	phpTaintWorker = a
}

// phpTaintAnalyzerReady reports whether an isolated analyzer is available.
//
// The consumer does not dispatch without one. Analysis cannot safely happen in
// this process, so the alternative would be recording every candidate file as
// an unexamined gap -- turning "this feature is not active here" into a
// per-file coverage report on every scan, which tells an operator nothing they
// can act on. A gap is for content that should have been examined and was not.
func phpTaintAnalyzerReady() bool {
	phpTaintWorkerMu.RLock()
	defer phpTaintWorkerMu.RUnlock()
	return phpTaintWorker != nil
}

// defaultPHPTaintAnalyze routes to the supervised worker, and reports a
// coverage gap when there is none.
//
// It deliberately does NOT fall back to calling phptaint.Analyze here. The
// parser can enter an infinite loop on attacker-controlled input; a loop is not
// a panic, so recover() cannot catch it, and the parser never checks context,
// so no deadline in this process can stop it. An in-process fallback would take
// a core from the daemon permanently the first time a crafted file was scanned
// -- which is the entire failure this indirection exists to prevent. Reporting
// a gap loses coverage on that file; the fallback would lose the daemon.
func defaultPHPTaintAnalyze(ctx context.Context, src []byte) phptaint.Report {
	phpTaintWorkerMu.RLock()
	worker := phpTaintWorker
	phpTaintWorkerMu.RUnlock()
	if worker == nil {
		return phptaint.Report{
			Status: phptaint.StatusWorkerFailure,
			Reason: "no isolated php analyzer configured; content not examined",
		}
	}
	return worker.Analyze(ctx, src)
}

// phpTaintAnalyze is indirected so tests can substitute the analyzer at the
// adapter boundary: forcing a panic or a specific status proves containment
// without needing a live worker or pathological PHP.
var phpTaintAnalyze = defaultPHPTaintAnalyze

// runPHPTaintAnalysis is the adapter recovery boundary around the analyzer
// call. The analyzer converts its own internal panics to StatusPanic, but a
// panic in adapter-side code around the call must have the same contained
// outcome instead of escaping through the owning check.
func runPHPTaintAnalysis(ctx context.Context, data []byte) (report phptaint.Report) {
	defer func() {
		if r := recover(); r != nil {
			report = phptaint.Report{Status: phptaint.StatusPanic, Reason: "panic"}
		}
	}()
	return phpTaintAnalyze(ctx, data)
}
