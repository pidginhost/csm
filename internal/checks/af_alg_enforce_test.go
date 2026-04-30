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
				_, _ = f.WriteString("algif_aead 16384 0 - Live 0x0\naf_alg 16384 1 - Live 0x0\n")
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
	if !modprobeCalled || !res.ModuleUnloaded {
		t.Errorf("modprobe -r should have been called; res=%+v called=%v", res, modprobeCalled)
	}
	if res.Action != EnforceActionUnloadModules {
		t.Errorf("Action = %v, want UnloadModules", res.Action)
	}
}

func TestEnforceAFAlgBlocked_ContinuesWhenUnloadFails(t *testing.T) {
	// modprobe -r returns non-zero (module in use). RunAllowNonZero
	// swallows non-zero exits as nil errors, so the wrapper should
	// proceed normally and report the action as attempted.
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
			return []byte("modprobe: FATAL: Module algif_aead is in use.\n"), nil
		},
	})

	res, err := enforceAFAlgBlocked()
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !res.ModuleUnloaded {
		// We attempted; whether it succeeded is observable on the
		// next tick by re-reading /proc/modules. The result reports
		// the attempt, not the outcome.
		t.Errorf("ModuleUnloaded should be true (attempted); res=%+v", res)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "in use") {
		t.Errorf("Notes should preserve modprobe stderr for operator; got %v", res.Notes)
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
