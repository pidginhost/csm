package checks

import (
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
