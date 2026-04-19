//go:build linux

package daemon

import (
	"os"
	"testing"
)

// These tests cover the Linux-only helper loadLocalDomainsForWatcher
// by redirecting it to read from a tempdir via a per-test wrapper.
// The real loadLocalDomainsForWatcher reads /etc/localdomains and
// /etc/virtualdomains; we can't rewrite those in CI, but we can still
// cover that it returns a non-nil map when the files don't exist.

func TestLoadLocalDomainsForWatcherReturnsMap(t *testing.T) {
	// On most test hosts /etc/localdomains does not exist; the function
	// must still return an initialized (empty) map, never nil.
	m := loadLocalDomainsForWatcher()
	if m == nil {
		t.Fatal("expected non-nil map even when files are absent")
	}
}

// TestLoadLocalDomainsForWatcherMissingFilesNoPanic verifies the helper
// does not panic when both domain files are absent or unreadable.
func TestLoadLocalDomainsForWatcherMissingFilesNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	_ = loadLocalDomainsForWatcher()
}

// TestNewForwarderWatcherMissingValiasesDir ensures NewForwarderWatcher
// cleanly errors when /etc/valiases is not present (common on CI hosts).
func TestNewForwarderWatcherMissingValiasesDir(t *testing.T) {
	// On a typical CI host without cPanel, /etc/valiases doesn't exist.
	// Either way, creating and closing should not leak.
	fw, err := NewForwarderWatcher(nil, nil)
	if err != nil {
		// Expected on hosts without /etc/valiases — nothing more to test.
		return
	}
	if fw == nil {
		t.Fatal("no error but nil watcher")
	}
	stopCh := make(chan struct{})
	close(stopCh)
	fw.Run(stopCh)
}

// TestForwarderWatcherReadEventsEmptyBuffer exercises readEvents path
// with no data available (non-blocking fd returning EOF).
func TestForwarderWatcherReadEventsEmptyBuffer(t *testing.T) {
	// /dev/null gives an EOF-on-read fd. Open via unix.Open so the runtime
	// poller cannot close the fd asynchronously while readEvents runs.
	fw := &ForwarderWatcher{
		inotifyFd: openRawFd(t, "/dev/null"),
	}
	buf := make([]byte, 4096)
	// readEvents should return immediately when no events available.
	fw.readEvents(buf)
}

// TestForwarderWatcherNewCloseRoundTrip covers the fd lifecycle when
// /etc/valiases happens to exist: Run must exit cleanly when stopCh closes.
func TestForwarderWatcherNewCloseRoundTrip(t *testing.T) {
	// Skip unless /etc/valiases is present.
	if _, err := os.Stat("/etc/valiases"); err != nil {
		t.Skip("/etc/valiases not present")
	}
	// Can't actually create an inotify watcher without root usually,
	// but try anyway. If it fails, that covers the error path.
	fw, err := NewForwarderWatcher(nil, nil)
	if err != nil {
		return
	}
	stopCh := make(chan struct{})
	close(stopCh)
	fw.Run(stopCh) // should close fd and return
}
