//go:build !linux

package daemon

import (
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/queuehealth"
)

// FileMonitor stub for non-Linux platforms.
type FileMonitor struct{}

func NewFileMonitor(_ *config.Config, _ chan<- alert.Finding) (*FileMonitor, error) {
	return nil, fmt.Errorf("fanotify not available on this platform")
}

func (fm *FileMonitor) Run(_ <-chan struct{})     {}
func (fm *FileMonitor) Stop()                     {}
func (fm *FileMonitor) registerMetrics()          {}
func (fm *FileMonitor) WatchScopeSummary() string { return "" }

func (fm *FileMonitor) queueStatuses(_ time.Time) map[string]queuehealth.Status { return nil }
