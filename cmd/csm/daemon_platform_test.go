package main

import (
	"os"
	"os/exec"
	"testing"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/obs"
	"github.com/pidginhost/csm/internal/platform"
)

// Sentry initialisation tags every event with the detected platform, which
// caches a detection. The operator's web_server override must already be in
// force by then, or every daemon start silently runs on the probe's answer.
func TestDaemonStartupKeepsPlatformOverridesWithSentryEnabled(t *testing.T) {
	// Sentry startup is process-wide and has no shutdown that resets obs.
	// Keep its client, scope and enabled flag out of the remaining tests.
	const childEnv = "CSM_TEST_SENTRY_STARTUP"
	if os.Getenv(childEnv) != "1" {
		enabledBefore := obs.Enabled()
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), exe, "-test.run=^"+t.Name()+"$")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("startup subprocess: %v\n%s", err, out)
		}
		if obs.Enabled() != enabledBefore {
			t.Error("startup test changed telemetry state for subsequent tests")
		}
		return
	}
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	t.Cleanup(obs.Flush)

	cfg := &config.Config{}
	cfg.WebServer.Type = "nginx"
	cfg.Sentry.Enabled = true
	// Reserved loopback port that never answers; Init does not connect.
	cfg.Sentry.DSN = "http://public@127.0.0.1:1/1"

	if err := initDaemonPlatform(cfg, "dev", ""); err != nil {
		t.Fatalf("initDaemonPlatform: %v", err)
	}
	if !obs.Enabled() {
		t.Fatal("Sentry was not enabled in the startup subprocess")
	}
	if got := platform.Detect().WebServer; got != platform.WSNginx {
		t.Fatalf("detected web server = %q, want the configured override %q", got, platform.WSNginx)
	}
}

// Without Sentry the same prelude must still install the override exactly
// once and report success.
func TestDaemonStartupInstallsOverridesWithoutSentry(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)

	cfg := &config.Config{}
	cfg.WebServer.Type = "litespeed"
	if err := initDaemonPlatform(cfg, "dev", ""); err != nil {
		t.Fatalf("initDaemonPlatform: %v", err)
	}
	if got := platform.Detect().WebServer; got != platform.WSLiteSpeed {
		t.Fatalf("detected web server = %q, want %q", got, platform.WSLiteSpeed)
	}
}
