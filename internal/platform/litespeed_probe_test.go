package platform

import (
	"reflect"
	"testing"
	"time"
)

// cPanel host booting before lsws is up: the Apache binary is present (cPanel
// always compiles httpd for config generation), nothing is running yet, and
// the LiteSpeed binary is on disk. The bare selectWebServer picks Apache; the
// litespeed-binary fallback must correct it to LiteSpeed so the log/modsec
// watchers tail the server cPanel actually serves through. This is the
// historical boot-order misdetect incident.
func TestLiteSpeedBinaryFallbackCorrectsBootMisdetect(t *testing.T) {
	running := map[string]bool{} // nothing up yet
	base := selectWebServer(PanelCPanel, running, true /*apache bin*/, false)
	if base != WSApache {
		t.Fatalf("precondition: bare select should pick apache, got %q", base)
	}
	got := liteSpeedBinaryFallback(base, running, true /*lsws binary present*/)
	if got != WSLiteSpeed {
		t.Errorf("lsws binary present + nothing running must correct to litespeed, got %q", got)
	}
}

// A LiteSpeed binary on disk must NOT override a web server that is actually
// running: real Apache serving means Apache, even if lsws is also installed.
func TestLiteSpeedBinaryFallbackKeepsRunningApache(t *testing.T) {
	running := map[string]bool{"httpd": true}
	got := liteSpeedBinaryFallback(WSApache, running, true)
	if got != WSApache {
		t.Errorf("running apache must win over installed-but-not-running litespeed, got %q", got)
	}
}

// No LiteSpeed binary: detection is left exactly as selectWebServer decided.
func TestLiteSpeedBinaryFallbackNoBinaryNoChange(t *testing.T) {
	if got := liteSpeedBinaryFallback(WSApache, map[string]bool{}, false); got != WSApache {
		t.Errorf("no lsws binary must leave detection unchanged, got %q", got)
	}
	if got := liteSpeedBinaryFallback(WSNone, map[string]bool{}, false); got != WSNone {
		t.Errorf("no lsws binary must leave WSNone unchanged, got %q", got)
	}
}

// An already-detected LiteSpeed (running) stays LiteSpeed through the fallback.
func TestLiteSpeedBinaryFallbackIdempotentOnLiteSpeed(t *testing.T) {
	running := map[string]bool{"lshttpd": true}
	if got := liteSpeedBinaryFallback(WSLiteSpeed, running, true); got != WSLiteSpeed {
		t.Errorf("running litespeed must stay litespeed, got %q", got)
	}
}

// Refresh re-runs detection with overrides and updates the cached Detect()
// result, so a host that mis-detected the web server at boot self-heals on a
// later refresh instead of staying wrong for the process lifetime. An operator
// web_server.type pin must keep winning through Refresh.
func TestRefreshAppliesOverrideAndUpdatesCache(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	if !SetOverrides(Overrides{WebServer: wsPtr(WSLiteSpeed)}) {
		t.Fatal("SetOverrides before Detect should succeed")
	}
	if got := Detect().WebServer; got != WSLiteSpeed {
		t.Fatalf("Detect should honor override, got %q", got)
	}
	if got := Refresh().WebServer; got != WSLiteSpeed {
		t.Errorf("Refresh must keep operator override, got %q", got)
	}
	if got := Detect().WebServer; got != WSLiteSpeed {
		t.Errorf("cache after Refresh must reflect the operator override, got %q", got)
	}
}

// Refresh's return value and the subsequently-cached Detect() value must agree
// (the refresh replaces the cache atomically).
func TestRefreshCacheStaysConsistent(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	_ = Detect() // populate cache
	got := Refresh()
	if !reflect.DeepEqual(Detect(), got) {
		t.Errorf("Detect() after Refresh must equal the Refresh result")
	}
}

func TestSetOverridesWaitsForInProgressDetection(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	detectMu.Lock()
	locked := true
	defer func() {
		if locked {
			detectMu.Unlock()
		}
	}()

	done := make(chan bool, 1)
	go func() {
		done <- SetOverrides(Overrides{WebServer: wsPtr(WSLiteSpeed)})
	}()

	select {
	case ok := <-done:
		t.Fatalf("SetOverrides returned %v while detection was in progress", ok)
	case <-time.After(25 * time.Millisecond):
	}

	detectedFlag.Store(true)
	detectMu.Unlock()
	locked = false

	if ok := <-done; ok {
		t.Fatal("SetOverrides should reject an override once in-progress detection has completed")
	}
}
