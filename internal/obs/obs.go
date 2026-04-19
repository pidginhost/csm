// Package obs centralises crash reporting and selective error capture via
// Sentry. Init is a one-shot called from the daemon entry point; after
// that, callers use Go/SafeGo to launch goroutines with panic recovery
// and Capture/CaptureMsg to forward selected errors.
//
// When Sentry is disabled or the DSN is empty, every function becomes a
// no-op wrapper with the same semantics as a plain `go func()` call,
// so guarded call sites work unchanged in tests and in operator
// builds that opt out of telemetry.
package obs

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

var enabled atomic.Bool

// flushTimeout bounds how long shutdown flushes block before giving up.
// Sentry enforces its own deadline on Flush; we pass this value so
// stuck HTTP calls don't hang systemd past TimeoutStopSec.
const flushTimeout = 2 * time.Second

// Init configures the Sentry SDK once at daemon startup. Returns nil if
// Sentry is disabled or the DSN is empty so callers can treat init as
// optional. Safe to call when cfg is nil.
func Init(cfg *config.Config, version, buildHash string) error {
	if cfg == nil || !cfg.Sentry.Enabled || cfg.Sentry.DSN == "" {
		return nil
	}

	env := cfg.Sentry.Environment
	if env == "" {
		env = "production"
	}
	rate := cfg.Sentry.SampleRate
	if rate <= 0 {
		rate = 1.0
	}
	hostname, _ := os.Hostname()
	release := "csm@" + version
	if buildHash != "" && buildHash != "unknown" {
		release = release + "+" + buildHash
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              cfg.Sentry.DSN,
		Environment:      env,
		Release:          release,
		ServerName:       hostname,
		SampleRate:       rate,
		TracesSampleRate: 0.0,
		Debug:            cfg.Sentry.Debug,
		AttachStacktrace: true,
	})
	if err != nil {
		return fmt.Errorf("sentry init: %w", err)
	}

	info := platform.Detect()
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetTag("os", string(info.OS))
		if info.OSVersion != "" {
			scope.SetTag("os_version", info.OSVersion)
		}
		if info.Panel != "" {
			scope.SetTag("panel", string(info.Panel))
		}
		if info.WebServer != "" {
			scope.SetTag("webserver", string(info.WebServer))
		}
	})

	enabled.Store(true)
	return nil
}

// Enabled reports whether Init succeeded and Sentry is live.
func Enabled() bool { return enabled.Load() }

// Flush waits for queued events to be sent before returning. Call from
// shutdown paths before exit. Safe to call when Sentry is disabled.
func Flush() {
	if !enabled.Load() {
		return
	}
	sentry.Flush(flushTimeout)
}

// Go launches fn in a new goroutine. A panic in fn is captured with the
// given component tag, the event is flushed, and the panic is
// re-raised so the existing crash-and-systemd-restart behavior is
// preserved. Use this for long-lived supervisor goroutines where a
// silent death would leave the daemon in a degraded state.
func Go(component string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				report(component, r)
				panic(r)
			}
		}()
		fn()
	}()
}

// SafeGo is Go but swallows the panic after capture. Use this for
// per-request handlers (socket accept, HTTP request) where one bad
// input should not crash the whole daemon.
func SafeGo(component string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				report(component, r)
			}
		}()
		fn()
	}()
}

// Capture sends an error to Sentry with a component tag. No-op when
// disabled or err is nil. Reserve for unexpected states and invariant
// violations; expected-failure errors (permission denied, transient
// network) should stay out of Sentry to avoid noise.
func Capture(component string, err error) {
	if !enabled.Load() || err == nil {
		return
	}
	sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetTag("component", component)
		sentry.CaptureException(err)
	})
}

// CaptureMsg is Capture for string-only events (e.g. invariant
// violations without a wrapped error).
func CaptureMsg(component, msg string) {
	if !enabled.Load() {
		return
	}
	sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetTag("component", component)
		sentry.CaptureMessage(msg)
	})
}

func report(component string, r any) {
	if !enabled.Load() {
		return
	}
	sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetTag("component", component)
		sentry.CurrentHub().Recover(r)
	})
	sentry.Flush(flushTimeout)
}
