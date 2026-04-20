package obs

import (
	"errors"
	"sync"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// restoreEnabledOnCleanup flips the package-level enabled flag back
// to false after a test that toggled it true. Tests that don't touch
// enabled don't need this helper.
func restoreEnabledOnCleanup(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { enabled.Store(false) })
}

// TestInitHappyPath exercises every branch inside Init: DSN present +
// Enabled=true, empty Environment defaults to "production", non-positive
// SampleRate defaults to 1.0, buildHash that is neither "" nor "unknown"
// appends to the release string. Platform tags are populated from
// platform.Detect() on whatever OS the test runs on.
func TestInitHappyPath(t *testing.T) {
	restoreEnabledOnCleanup(t)

	cfg := &config.Config{}
	cfg.Sentry.Enabled = true
	// DSN points at a reserved-loopback port that will never answer.
	// sentry.Init parses and accepts it; later Flush/Capture calls
	// rely on the SDK's internal timeout + our flushTimeout.
	cfg.Sentry.DSN = "http://public@127.0.0.1:1/1"
	cfg.Sentry.Environment = "" // exercise env default branch
	cfg.Sentry.SampleRate = 0   // exercise rate-default branch
	cfg.Sentry.Debug = false

	if err := Init(cfg, "2.6.0", "abcdef12"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !Enabled() {
		t.Fatal("Enabled() stayed false after successful Init")
	}
}

func TestInitNonDefaultEnvironmentAndSampleRate(t *testing.T) {
	restoreEnabledOnCleanup(t)

	cfg := &config.Config{}
	cfg.Sentry.Enabled = true
	cfg.Sentry.DSN = "http://public@127.0.0.1:1/1"
	cfg.Sentry.Environment = "staging"
	cfg.Sentry.SampleRate = 0.5

	if err := Init(cfg, "dev", ""); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !Enabled() {
		t.Fatal("Enabled() stayed false after successful Init")
	}
}

// The release string folds buildHash in when it is non-empty and not
// the sentinel "unknown". The "unknown" branch is its own line in
// Init; assert both branches survive the Init call without error.
func TestInitBuildHashUnknownBranch(t *testing.T) {
	restoreEnabledOnCleanup(t)

	cfg := &config.Config{}
	cfg.Sentry.Enabled = true
	cfg.Sentry.DSN = "http://public@127.0.0.1:1/1"

	if err := Init(cfg, "dev", "unknown"); err != nil {
		t.Fatalf("Init with buildHash=unknown: %v", err)
	}
}

// sentry.Init itself can fail on a truly malformed DSN. The wrap must
// return a "sentry init:" prefixed error without flipping enabled on.
func TestInitPropagatesSentryInitError(t *testing.T) {
	restoreEnabledOnCleanup(t)

	cfg := &config.Config{}
	cfg.Sentry.Enabled = true
	// Missing scheme/project — sentry.Init rejects this.
	cfg.Sentry.DSN = "not-a-valid-dsn"

	err := Init(cfg, "dev", "")
	if err == nil {
		t.Fatal("Init accepted a malformed DSN")
	}
	if Enabled() {
		t.Error("Enabled() flipped true after a rejected Init")
	}
}

// --- enabled-state helpers --------------------------------------------

// For the downstream helpers (Flush, Capture, CaptureMsg, report) the
// branch of interest is the enabled=true path. Toggling enabled
// without calling sentry.Init leaves the default-hub no-op SDK in
// place, which is safe: sentry.Flush / WithScope / CaptureException
// are all defined to be silent no-ops when there is no active client.

func TestFlushEnabledBranch(t *testing.T) {
	restoreEnabledOnCleanup(t)
	enabled.Store(true)
	// Must not block beyond flushTimeout and must not panic.
	Flush()
}

func TestCaptureNilErrorIsNoopEvenWhenEnabled(t *testing.T) {
	restoreEnabledOnCleanup(t)
	enabled.Store(true)
	// err==nil short-circuits before touching sentry.WithScope.
	Capture("test", nil)
}

func TestCaptureEnabledBranch(t *testing.T) {
	restoreEnabledOnCleanup(t)
	enabled.Store(true)
	Capture("test-component", errors.New("boom"))
}

func TestCaptureMsgEnabledBranch(t *testing.T) {
	restoreEnabledOnCleanup(t)
	enabled.Store(true)
	CaptureMsg("test-component", "invariant violated")
}

// report() is called from SafeGo's and Go's deferred recover. With
// enabled=true the full WithScope + Recover + Flush chain runs.
func TestSafeGoInvokesReportWhenEnabled(t *testing.T) {
	restoreEnabledOnCleanup(t)
	enabled.Store(true)

	var wg sync.WaitGroup
	wg.Add(1)
	SafeGo("test-component", func() {
		defer wg.Done()
		panic("boom-enabled")
	})
	wg.Wait()
}
