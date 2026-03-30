//go:build !linux

package daemon

import (
	"fmt"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
	"github.com/pidginhost/cpanel-security-monitor/internal/config"
	"github.com/pidginhost/cpanel-security-monitor/internal/emailav"
)

// SpoolWatcher is a no-op on non-Linux platforms.
type SpoolWatcher struct{}

func NewSpoolWatcher(_ *config.Config, _ chan<- alert.Finding, _ *emailav.Orchestrator, _ *emailav.Quarantine) (*SpoolWatcher, error) {
	return nil, fmt.Errorf("spool watcher requires Linux (fanotify)")
}

func (sw *SpoolWatcher) Run()              {}
func (sw *SpoolWatcher) Stop()             {}
func (sw *SpoolWatcher) PermissionMode() bool { return false }
