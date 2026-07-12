//go:build linux && bpf

package daemon

import (
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	csmlog "github.com/pidginhost/csm/internal/log"
)

func emitBPFReaderError(alertCh chan<- alert.Finding, monitor string, err error) {
	finding := alert.Finding{
		Severity:  alert.High,
		Check:     "bpf_ringbuf_error",
		Message:   fmt.Sprintf("%s BPF event reader failed; automatic retry is active", monitor),
		Details:   err.Error(),
		Timestamp: time.Now(),
	}
	select {
	case alertCh <- finding:
	default:
		csmlog.Warn("bpf reader error finding dropped", "monitor", monitor, "err", err)
	}
}
