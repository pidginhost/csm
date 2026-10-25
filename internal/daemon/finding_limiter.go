package daemon

import (
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// isolationAlertInterval spaces email_av_isolation_unavailable findings: the
// condition lasts until an operator fixes the host, so once an hour is enough.
const isolationAlertInterval = time.Hour

// findingLimiter emits each check at most once per interval. Only a
// delivered finding uses up the allowance, so a full alert queue cannot hide
// a condition for a whole interval.
type findingLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (l *findingLimiter) emit(ch chan<- alert.Finding, check string, severity alert.Severity, interval time.Duration, message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if last, ok := l.last[check]; ok && time.Since(last) < interval {
		return
	}
	now := time.Now()
	if alert.TryEnqueue(ch, alert.Finding{Severity: severity, Check: check, Message: message, Timestamp: now}) {
		if l.last == nil {
			l.last = make(map[string]time.Time)
		}
		l.last[check] = now
	}
}
