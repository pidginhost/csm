package daemon

import (
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
)

// emitBPFUnavailableFinding posts an operator-visible warning when a
// BPF-backed live monitor cannot start the kernel-attached path. fallback is
// the selected non-BPF backend; empty means no live fallback is active.
func emitBPFUnavailableFinding(alertCh chan<- alert.Finding, feature, choice, fallback string, err error) bool {
	if alertCh == nil {
		return false
	}
	sev := alert.Warning
	if choice == bpf.BackendBPF || fallback == "" {
		sev = alert.High
	}
	status := "no live fallback active"
	if fallback != "" {
		status = fmt.Sprintf("running on %s fallback", fallback)
	}
	details := ""
	if err != nil {
		details = err.Error()
	}
	f := alert.Finding{
		Severity:  sev,
		Check:     "bpf_unavailable",
		Message:   fmt.Sprintf("BPF backend unavailable for %s (operator choice=%q); %s", feature, choice, status),
		Details:   details,
		Timestamp: time.Now(),
	}
	select {
	case alertCh <- f:
		return true
	default:
		return false
	}
}
