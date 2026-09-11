//go:build !linux

package daemon

import (
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailav"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// SpoolWatcher is a no-op on non-Linux platforms.
type SpoolWatcher struct{}

func NewSpoolWatcher(_ *config.Config, _ chan<- alert.Finding, _ *emailav.Orchestrator, _ *emailav.Quarantine) (*SpoolWatcher, error) {
	return nil, fmt.Errorf("spool watcher requires Linux (fanotify)")
}

func (sw *SpoolWatcher) Run()                 {}
func (sw *SpoolWatcher) Stop()                {}
func (sw *SpoolWatcher) PermissionMode() bool { return false }

func (sw *SpoolWatcher) inheritQueueHealth(_ *SpoolWatcher)                      {}
func (sw *SpoolWatcher) queueStatuses(_ time.Time) map[string]queuehealth.Status { return nil }
