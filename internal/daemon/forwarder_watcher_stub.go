//go:build !linux

package daemon

import (
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// ForwarderWatcher is a no-op on non-Linux platforms.
type ForwarderWatcher struct{}

// NewForwarderWatcher returns an error on non-Linux platforms.
func NewForwarderWatcher(_ chan<- alert.Finding, _ []string) (*ForwarderWatcher, error) {
	return nil, fmt.Errorf("forwarder watcher requires Linux (inotify)")
}

// Run is a no-op on non-Linux platforms.
func (fw *ForwarderWatcher) Run(_ <-chan struct{}) {}

func (fw *ForwarderWatcher) QueueStatuses(time.Time) map[string]queuehealth.Status { return nil }
