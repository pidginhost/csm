package daemon

import (
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/platform"
)

func TestShouldWatchEximMainlogCPanelAlways(t *testing.T) {
	statCalled := false
	got := shouldWatchEximMainlog(platform.Info{Panel: platform.PanelCPanel}, func(string) (os.FileInfo, error) {
		statCalled = true
		return nil, os.ErrNotExist
	})
	if !got {
		t.Fatal("cPanel hosts must watch exim_mainlog even before it exists")
	}
	if statCalled {
		t.Fatal("cPanel path should not depend on os.Stat")
	}
}

func TestShouldWatchEximMainlogNonCPanelWhenPresent(t *testing.T) {
	got := shouldWatchEximMainlog(platform.Info{}, func(path string) (os.FileInfo, error) {
		if path != eximMainlogPath {
			t.Fatalf("stat path = %q, want %q", path, eximMainlogPath)
		}
		return nil, nil
	})
	if !got {
		t.Fatal("non-cPanel Exim hosts with exim_mainlog should be watched")
	}
}

func TestShouldWatchEximMainlogNonCPanelSkipsMissing(t *testing.T) {
	got := shouldWatchEximMainlog(platform.Info{}, func(string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	})
	if got {
		t.Fatal("non-cPanel hosts without exim_mainlog should not start a retry loop")
	}
}
