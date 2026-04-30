package checks

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestDecideAFAlgEnforcement_AdvisoryModeWhenMarkerAbsent(t *testing.T) {
	cases := []struct {
		loaded bool
		desc   string
	}{
		{false, "marker absent, modules unloaded"},
		{true, "marker absent, modules loaded"},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			if got := decideAFAlgEnforcement(false, false, c.loaded); got != EnforceActionNoop {
				t.Errorf("got %v, want EnforceActionNoop (advisory mode)", got)
			}
		})
	}
}

func TestDecideAFAlgEnforcement_NoopWhenEnforced(t *testing.T) {
	if got := decideAFAlgEnforcement(true, true, false); got != EnforceActionNoop {
		t.Errorf("got %v, want EnforceActionNoop (already enforced, nothing to do)", got)
	}
}

func TestDecideAFAlgEnforcement_RestoreMarkerWhenContentDrifted(t *testing.T) {
	if got := decideAFAlgEnforcement(true, false, false); got != EnforceActionRestoreMarker {
		t.Errorf("got %v, want EnforceActionRestoreMarker", got)
	}
}

func TestDecideAFAlgEnforcement_UnloadWhenMarkerValidButModulesLoaded(t *testing.T) {
	if got := decideAFAlgEnforcement(true, true, true); got != EnforceActionUnloadModules {
		t.Errorf("got %v, want EnforceActionUnloadModules", got)
	}
}

func TestDecideAFAlgEnforcement_RestoreAndUnloadWhenBothDrifted(t *testing.T) {
	if got := decideAFAlgEnforcement(true, false, true); got != EnforceActionRestoreAndUnload {
		t.Errorf("got %v, want EnforceActionRestoreAndUnload", got)
	}
}

const canonicalAFAlgMarkerForTest = `# CSM Copy Fail (CVE-2026-31431) mitigation — managed by CSM.
# Restored automatically by the af_alg_enforce critical-tier check.
# Remove this file (and run ` + "`csm harden --copy-fail`" + ` again) if you
# need to re-enable AF_ALG.
install algif_aead /bin/false
install af_alg /bin/false
`

func TestEnforceAFAlgBlocked_NoopWhenMarkerAbsent(t *testing.T) {
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{}) // no calls expected

	res, err := enforceAFAlgBlocked()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if res.Action != EnforceActionNoop {
		t.Errorf("Action = %v, want Noop", res.Action)
	}
	if res.MarkerWritten || res.ModuleUnloaded {
		t.Errorf("nothing should have been written or unloaded; res = %+v", res)
	}
}

func TestEnforceAFAlgBlocked_WritesMarkerOnDriftWhenMarkerExistsButContentBad(t *testing.T) {
	written := false
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == afAlgMarkerPath {
				return fakeFileInfo{name: name, size: 1}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if name == afAlgMarkerPath {
				return []byte("hand-edited junk\n"), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			// /proc/modules — return file with bridge only (no algif).
			if name == "/proc/modules" {
				f, err := os.CreateTemp(t.TempDir(), "modules")
				if err != nil {
					return nil, err
				}
				_, _ = f.WriteString("bridge 200704 0 - Live 0x0\n")
				_, _ = f.Seek(0, 0)
				return f, nil
			}
			return nil, os.ErrNotExist
		},
		writeFile: func(name string, data []byte, perm os.FileMode) error {
			if name != afAlgMarkerPath {
				t.Errorf("unexpected write to %q", name)
			}
			if string(data) != canonicalAFAlgMarkerForTest {
				t.Errorf("wrote drifted content; got %q", string(data))
			}
			if perm != 0o644 {
				t.Errorf("perm = %v, want 0644", perm)
			}
			written = true
			return nil
		},
	})
	withMockCmd(t, &mockCmd{}) // no modprobe expected

	res, err := enforceAFAlgBlocked()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !written || !res.MarkerWritten {
		t.Errorf("marker should have been written; res=%+v written=%v", res, written)
	}
	if res.ModuleUnloaded {
		t.Errorf("nothing was loaded; ModuleUnloaded should be false; res=%+v", res)
	}
	if res.Action != EnforceActionRestoreMarker {
		t.Errorf("Action = %v, want RestoreMarker", res.Action)
	}
}

func TestEnforceAFAlgBlocked_UnloadsModulesWhenMarkerValidButLoaded(t *testing.T) {
	// /proc/modules content shifts during the test: BEFORE modprobe -r the
	// modules are loaded; AFTER modprobe -r they are gone. This simulates a
	// successful unload. The wrapper observes both states (one read before
	// the action to decide what to do, one after to verify the result), so
	// the mock toggles based on whether modprobe has been invoked yet.
	modprobeCalled := false
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == afAlgMarkerPath {
				return fakeFileInfo{name: name, size: int64(len(canonicalAFAlgMarkerForTest))}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			if name == afAlgMarkerPath {
				return []byte(canonicalAFAlgMarkerForTest), nil
			}
			return nil, os.ErrNotExist
		},
		open: func(name string) (*os.File, error) {
			if name == "/proc/modules" {
				f, err := os.CreateTemp(t.TempDir(), "modules")
				if err != nil {
					return nil, err
				}
				if !modprobeCalled {
					_, _ = f.WriteString("algif_aead 16384 0 - Live 0x0\naf_alg 16384 1 - Live 0x0\n")
				} else {
					_, _ = f.WriteString("bridge 200704 0 - Live 0x0\n")
				}
				_, _ = f.Seek(0, 0)
				return f, nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			if name == "modprobe" && len(args) >= 1 && args[0] == "-r" {
				modprobeCalled = true
				return nil, nil
			}
			return nil, errors.New("unexpected command")
		},
	})

	res, err := enforceAFAlgBlocked()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !modprobeCalled {
		t.Error("modprobe -r should have been called")
	}
	if !res.ModuleUnloaded {
		t.Errorf("ModuleUnloaded should be true (post-call /proc/modules clean); res=%+v", res)
	}
	if res.Action != EnforceActionUnloadModules {
		t.Errorf("Action = %v, want UnloadModules", res.Action)
	}
	if len(res.Notes) != 0 {
		t.Errorf("successful unload should produce no notes; got %v", res.Notes)
	}
}

func TestEnforceAFAlgBlocked_ReportsStuckModuleWhenUnloadFails(t *testing.T) {
	// modprobe -r returns non-zero (module in use). The wrapper observes
	// failure via the post-call /proc/modules re-read — modules are still
	// there. ModuleUnloaded must be false; Notes must name the stuck module.
	// (RunAllowNonZero swallows non-zero exits AND captures stdout-only via
	// .Output(), so modprobe's stderr is not visible to us — we rely on the
	// observable kernel state instead.)
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == afAlgMarkerPath {
				return fakeFileInfo{name: name, size: 1}, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			return []byte(canonicalAFAlgMarkerForTest), nil
		},
		open: func(name string) (*os.File, error) {
			// /proc/modules consistently reports algif_aead loaded — the
			// module is "in use" and modprobe -r cannot remove it.
			if name == "/proc/modules" {
				f, err := os.CreateTemp(t.TempDir(), "modules")
				if err != nil {
					return nil, err
				}
				_, _ = f.WriteString("algif_aead 16384 1 - Live 0x0\n")
				_, _ = f.Seek(0, 0)
				return f, nil
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{
		runAllowNonZero: func(name string, args ...string) ([]byte, error) {
			return nil, nil // simulates exit-1 swallowed by RunAllowNonZero
		},
	})

	res, err := enforceAFAlgBlocked()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if res.ModuleUnloaded {
		t.Errorf("ModuleUnloaded must be false when post-call /proc/modules still shows the module; res=%+v", res)
	}
	notes := strings.Join(res.Notes, "\n")
	if !strings.Contains(notes, "algif_aead") {
		t.Errorf("Notes must name the stuck module so the operator can investigate; got %v", res.Notes)
	}
	if !strings.Contains(notes, "still loaded") {
		t.Errorf("Notes should include the marker phrase \"still loaded\" so the alert pipeline can group these events; got %v", res.Notes)
	}
}

func TestEnforceAFAlgBlocked_ReturnsErrorWhenStatFailsUnexpectedly(t *testing.T) {
	// EACCES on /etc/modprobe.d/ (e.g., chattr +i applied or restrictive
	// chmod) must NOT be silently treated as advisory mode — the operator
	// has to see the error so they know enforcement is broken.
	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == afAlgMarkerPath {
				return nil, os.ErrPermission
			}
			return nil, os.ErrNotExist
		},
	})
	withMockCmd(t, &mockCmd{})

	_, err := enforceAFAlgBlocked()
	if err == nil {
		t.Fatal("EACCES on stat must be surfaced as an error, not silently ignored")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("err should wrap os.ErrPermission; got %v", err)
	}
}

func TestCanonicalMarkerContentDoesNotMatchHandEdit(t *testing.T) {
	// Sanity: validateMarkerContent must reject any content other than
	// the canonical one — including legitimate hand-written variants
	// like `blacklist algif_aead\n` that the audit accepts. The
	// enforcement check is stricter on purpose: it rewrites to the
	// canonical form so future reads are deterministic.
	if validateMarkerContent([]byte("blacklist algif_aead\n")) {
		t.Error("hand-written blacklist directive should NOT match canonical CSM-managed content")
	}
	if !validateMarkerContent([]byte(canonicalAFAlgMarker)) {
		t.Error("canonicalAFAlgMarker constant should validate")
	}
}
