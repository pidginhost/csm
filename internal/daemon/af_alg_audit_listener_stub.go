//go:build !linux

package daemon

import (
	"context"
	"fmt"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
)

// AFAlgAuditListener is a no-op stub on non-Linux platforms. The real
// implementation lives in af_alg_audit_listener.go behind //go:build
// linux because it relies on inotify via golang.org/x/sys/unix.
type AFAlgAuditListener struct{}

// Mode reports the backend kind. Stub matches the Linux backend's name
// so consumers can render a uniform value (it just won't reach this on
// a non-Linux build because NewAFAlgAuditListener errors out below).
func (l *AFAlgAuditListener) Mode() string { return "auditd-tail" }

// EventCount is always zero on the stub.
func (l *AFAlgAuditListener) EventCount() uint64 { return 0 }

// Run is a no-op. The Linux build does the real work.
func (l *AFAlgAuditListener) Run(_ context.Context) {}

// NewAFAlgAuditListener returns a sentinel error on non-Linux so the
// daemon's startup gate logs a "not supported" line and skips the
// listener cleanly. CSM is Linux-only in production; this stub exists
// solely so dev builds on macOS compile without fanout to every call
// site.
func NewAFAlgAuditListener(_ chan<- alert.Finding, _ *config.Config) (*AFAlgAuditListener, error) {
	return nil, fmt.Errorf("af_alg audit listener requires Linux (inotify)")
}

// reactToAFAlgEvent is the no-op stub. The real implementation that
// invokes unix.Kill lives in af_alg_react.go behind //go:build linux.
func reactToAFAlgEvent(_ *config.Config, _ checks.AFAlgEvent) {}
