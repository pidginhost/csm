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
	oldServiceEnabled := mtaServiceEnabled
	mtaServiceEnabled = func(string) bool { return false }
	t.Cleanup(func() {
		mtaLookPath, mtaStat, mtaServiceActive = oldLookPath, oldStat, oldServiceActive
		mtaServiceEnabled = oldServiceEnabled
	})
}

func withEnabledMTAService(t *testing.T, enabled map[string]bool) {
	t.Helper()
	old := mtaServiceEnabled
	mtaServiceEnabled = func(unit string) bool { return enabled[unit] }
	t.Cleanup(func() { mtaServiceEnabled = old })
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

func TestDetectMTAStalwart(t *testing.T) {
	for _, tc := range []struct {
		name    string
		active  map[string]bool
		present map[string]bool
		want    MTAKind
	}{
		{"stalwart", map[string]bool{"stalwart": true}, nil, MTAStalwart},
		{"stalwart-mail", map[string]bool{"stalwart-mail": true}, nil, MTAStalwart},
		{"exim wins", map[string]bool{"exim": true, "stalwart": true}, nil, MTAExim},
		{"postfix wins", map[string]bool{"postfix": true, "stalwart": true}, nil, MTAPostfix},
		{"cpanel wins", map[string]bool{"stalwart": true}, map[string]bool{"/usr/local/cpanel/version": true}, MTAExim},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withMTAProbes(t, nil, tc.present)
			withActiveMTAService(t, tc.active)
			if got := DetectMTA(); got != tc.want {
				t.Errorf("DetectMTA() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestServiceActiveUsesProbe(t *testing.T) {
	withActiveMTAService(t, map[string]bool{"stalwart": true})
	if !ServiceActive("stalwart") || ServiceActive("dovecot") {
		t.Fatal("ServiceActive must report the probe's answer")
	}
}

// Stalwart still starting, restarting or crash-looping when CSM starts must
// not leave the host on the Postfix/Dovecot reader for the life of the
// process: an enabled unit counts once no Exim or Postfix service is active.
func TestDetectMTAStalwartEnabledButNotActive(t *testing.T) {
	withMTAProbes(t, map[string]bool{"postfix": true}, nil)
	withEnabledMTAService(t, map[string]bool{"stalwart": true})
	if got := DetectMTA(); got != MTAStalwart {
		t.Fatalf("enabled Stalwart with an installed Postfix binary: DetectMTA() = %q, want %q", got, MTAStalwart)
	}
	withActiveMTAService(t, map[string]bool{"exim": true})
	if got := DetectMTA(); got != MTAExim {
		t.Fatalf("an active Exim must win over an enabled Stalwart: DetectMTA() = %q", got)
	}
}

func TestDetectMTAStalwartMailUnitEnabled(t *testing.T) {
	withMTAProbes(t, nil, nil)
	withEnabledMTAService(t, map[string]bool{"stalwart-mail": true})
	if got := DetectMTA(); got != MTAStalwart {
		t.Fatalf("DetectMTA() = %q, want %q", got, MTAStalwart)
	}
}
