package platform

import (
	"os"
	"os/exec"
	"testing"
)

func withMTAProbes(t *testing.T, onPath map[string]bool, present map[string]bool) {
	t.Helper()
	oldLook, oldStat := mtaLookPath, mtaStat
	mtaLookPath = func(file string) (string, error) {
		if onPath[file] {
			return "/usr/sbin/" + file, nil
		}
		return "", exec.ErrNotFound
	}
	mtaStat = func(name string) (os.FileInfo, error) {
		if present[name] {
			return os.Stat(os.DevNull)
		}
		return nil, os.ErrNotExist
	}
	t.Cleanup(func() { mtaLookPath, mtaStat = oldLook, oldStat })
}

func TestDetectMTAReportsEximWhenOnPath(t *testing.T) {
	withMTAProbes(t, map[string]bool{"exim": true}, nil)
	if got := DetectMTA(); got != MTAExim {
		t.Errorf("DetectMTA() = %q, want %q", got, MTAExim)
	}
}

func TestDetectMTAReportsEximForDebianExim4(t *testing.T) {
	withMTAProbes(t, map[string]bool{"exim4": true}, nil)
	if got := DetectMTA(); got != MTAExim {
		t.Errorf("DetectMTA() = %q, want %q", got, MTAExim)
	}
}

func TestDetectMTAReportsPostfixWhenEximAbsent(t *testing.T) {
	withMTAProbes(t, map[string]bool{"postfix": true}, nil)
	if got := DetectMTA(); got != MTAPostfix {
		t.Errorf("DetectMTA() = %q, want %q", got, MTAPostfix)
	}
}

func TestDetectMTAPrefersEximWhenBothInstalled(t *testing.T) {
	withMTAProbes(t, map[string]bool{"exim": true, "postfix": true}, nil)
	if got := DetectMTA(); got != MTAExim {
		t.Errorf("DetectMTA() = %q, want %q", got, MTAExim)
	}
}

func TestDetectMTAFindsBinaryOutsidePath(t *testing.T) {
	// Package installs put the MTA in /usr/sbin, which is not on a
	// non-login PATH.
	withMTAProbes(t, nil, map[string]bool{"/usr/sbin/postfix": true})
	if got := DetectMTA(); got != MTAPostfix {
		t.Errorf("DetectMTA() = %q, want %q", got, MTAPostfix)
	}
}

func TestDetectMTAReportsUnknownWhenNoMTAInstalled(t *testing.T) {
	withMTAProbes(t, nil, nil)
	if got := DetectMTA(); got != MTAUnknown {
		t.Errorf("DetectMTA() = %q, want %q", got, MTAUnknown)
	}
}
