//go:build !linux

package daemon

import (
	"fmt"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// FileMonitor stub for non-Linux platforms.
type FileMonitor struct{}

func NewFileMonitor(_ *config.Config, _ chan<- alert.Finding) (*FileMonitor, error) {
	return nil, fmt.Errorf("fanotify not available on this platform")
}

func (fm *FileMonitor) Run(_ <-chan struct{}) {}
func (fm *FileMonitor) Stop()                 {}
