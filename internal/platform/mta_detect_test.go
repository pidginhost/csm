package platform

import (
	"os"
	"os/exec"
	"testing"
)

func withMTAProbes(t *testing.T, onPath map[string]bool, present map[string]bool) {
	t.Helper()
	oldLookPath, oldStat, oldServiceActive := mtaLookPath, mtaStat, mtaServiceActive
	mtaLookPath = func(file string) (string, error) {
		if onPath[file] {
			return "/usr/sbin/" + file, nil
		}
		return "", exec.ErrNotFound
	}
	mtaStat = func(name string) (os.FileInfo, error) {
		if present[name] {
			return os.Stat(os.Args[0])
		}
		return nil, os.ErrNotExist
	}
	mtaServiceActive = func(string) bool { return false }
	t.Cleanup(func() {
		mtaLookPath, mtaStat, mtaServiceActive = oldLookPath, oldStat, oldServiceActive
	})
}

func withActiveMTAService(t *testing.T, active map[string]bool) {
	t.Helper()
	old := mtaServiceActive
	mtaServiceActive = func(unit string) bool { return active[unit] }
	t.Cleanup(func() { mtaServiceActive = old })
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

func TestDetectMTAReportsEximOnCPanelWithPostfixInstalled(t *testing.T) {
	withMTAProbes(t, map[string]bool{"postfix": true}, map[string]bool{
		"/usr/local/cpanel/version": true,
	})
	if got := DetectMTA(); got != MTAExim {
		t.Errorf("DetectMTA() = %q, want %q", got, MTAExim)
	}
}

func TestDetectMTADoesNotGuessWhenBothAreInstalled(t *testing.T) {
	withMTAProbes(t, map[string]bool{"exim": true, "postfix": true}, nil)
	if got := DetectMTA(); got != MTAUnknown {
		t.Errorf("DetectMTA() = %q, want %q", got, MTAUnknown)
	}
}

func TestDetectMTAPrefersActivePostfixWhenBothAreInstalled(t *testing.T) {
	withMTAProbes(t, map[string]bool{"exim": true, "postfix": true}, nil)
	withActiveMTAService(t, map[string]bool{"postfix": true})
	if got := DetectMTA(); got != MTAPostfix {
		t.Errorf("DetectMTA() = %q, want %q", got, MTAPostfix)
	}
}

func TestDetectMTAPrefersEximWhenBothServicesAreActive(t *testing.T) {
	withMTAProbes(t, nil, nil)
	withActiveMTAService(t, map[string]bool{"exim": true, "postfix": true})
	if got := DetectMTA(); got != MTAExim {
		t.Errorf("DetectMTA() = %q, want %q", got, MTAExim)
	}
}

func TestDetectMTAIgnoresNonExecutableAbsolutePath(t *testing.T) {
	oldLookPath, oldStat, oldServiceActive := mtaLookPath, mtaStat, mtaServiceActive
	mtaLookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	mtaStat = func(name string) (os.FileInfo, error) {
		if name == "/usr/sbin/exim" {
			return os.Stat(os.DevNull)
		}
		return nil, os.ErrNotExist
	}
	mtaServiceActive = func(string) bool { return false }
	t.Cleanup(func() {
		mtaLookPath, mtaStat, mtaServiceActive = oldLookPath, oldStat, oldServiceActive
	})

	if got := DetectMTA(); got != MTAUnknown {
		t.Errorf("DetectMTA() = %q, want unknown for non-executable path", got)
	}
}

func TestDetectMTAFindsBinaryOutsidePath(t *testing.T) {
	withMTAProbes(t, nil, map[string]bool{"/usr/sbin/postfix": true})
	if got := DetectMTA(); got != MTAPostfix {
		t.Errorf("DetectMTA() = %q, want %q", got, MTAPostfix)
	}
}

func TestDetectMTAFindsExim4OutsidePath(t *testing.T) {
	withMTAProbes(t, nil, map[string]bool{"/usr/sbin/exim4": true})
	if got := DetectMTA(); got != MTAExim {
		t.Errorf("DetectMTA() = %q, want %q", got, MTAExim)
	}
}

func TestDetectMTAReportsUnknownWhenNoMTAInstalled(t *testing.T) {
	withMTAProbes(t, nil, nil)
	if got := DetectMTA(); got != MTAUnknown {
		t.Errorf("DetectMTA() = %q, want %q", got, MTAUnknown)
	}
}
