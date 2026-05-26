package daemon

import (
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
)

// emitBPFUnavailableFinding posts an operator-visible warning when a
// BPF-backed live monitor cannot start the kernel-attached path the
// operator asked for. Severity scales by intent:
//
//   - choice == "bpf": operator explicitly required BPF. Falling back
//     silently to legacy / none would let an operator believe live
//     enforcement is on when it is off. Emit High.
//   - choice == "auto" (or empty): operator left the default. The
//     daemon picked a working fallback; still surface a Warning so
//     operators on older kernels know which features are running on
//     the slower path.
//
// Non-blocking on a full alert channel: the matching info-level
// stderr log is the durable trail. Returns whether anything was
// emitted so callers can branch on it for tests.
func emitBPFUnavailableFinding(alertCh chan<- alert.Finding, feature, choice string, err error) bool {
	if alertCh == nil {
		return false
	}
	sev := alert.Warning
	if choice == bpf.BackendBPF {
		sev = alert.High
	}
	f := alert.Finding{
		Severity:  sev,
		Check:     "bpf_unavailable",
		Message:   fmt.Sprintf("BPF backend unavailable for %s (operator choice=%q); running on fallback", feature, choice),
		Details:   err.Error(),
		Timestamp: time.Now(),
	}
	select {
	case alertCh <- f:
		return true
	default:
		return false
	}
}
