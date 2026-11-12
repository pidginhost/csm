package daemon

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
	csmlog "github.com/pidginhost/csm/internal/log"
)

// captureWarnings returns the WARN lines the global logger writes while fn
// runs.
func captureWarnings(t *testing.T, fn func()) []string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = w
	csmlog.Init()
	defer func() {
		os.Stderr = original
		csmlog.Init()
	}()
	fn()
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	var warnings []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "WARN") {
			warnings = append(warnings, line)
		}
	}
	return warnings
}

func TestStartPlacementMonitorSelection(t *testing.T) {
	cases := []struct {
		name      string
		setting   string
		bpfErr    error
		fidOK     bool
		wantMode  string
		wantKind  string
		wantFound string // bpf_unavailable message part; empty: no finding
		wantSev   alert.Severity
		wantWarns int
		wantTries string // which starters ran, in order
	}{
		{"auto with BPF", "auto", nil, true, "bpf", bpf.BackendBPF, "", 0, 0, "b"},
		{"auto falls back to fanotify", "", bpf.ErrUnsupported, true, "legacy", bpf.BackendLegacy, "running on legacy fallback", alert.Warning, 0, "bf"},
		{"auto with neither", "auto", bpf.ErrUnsupported, false, "", bpf.BackendNone, "no live fallback active", alert.High, 1, "bf"},
		{"none", "none", nil, true, "", bpf.BackendNone, "", 0, 1, ""},
		{"legacy pins fanotify", "legacy", nil, true, "legacy", bpf.BackendLegacy, "", 0, 0, "f"},
		{"legacy without fanotify", "legacy", nil, false, "", bpf.BackendNone, "", 0, 1, "f"},
		{"bpf strict never falls back", "bpf", bpf.ErrUnsupported, true, "", bpf.BackendNone, "no live fallback active", alert.High, 2, "b"},
		{"unknown value runs auto", "potato", nil, true, "bpf", bpf.BackendBPF, "", 0, 1, "b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tries string
			oldBPF, oldFID := tryStartPlacementBPFFn, tryStartPlacementFIDFn
			t.Cleanup(func() { tryStartPlacementBPFFn, tryStartPlacementFIDFn = oldBPF, oldFID })
			tryStartPlacementBPFFn = func(context.Context, *FileMonitor) (bpf.Backend, error) {
				tries += "b"
				if tc.bpfErr != nil {
					return nil, tc.bpfErr
				}
				return &fakeConnBackend{mode: bpf.BackendBPF}, nil
			}
			tryStartPlacementFIDFn = func(context.Context, *FileMonitor) bpf.Backend {
				tries += "f"
				if !tc.fidOK {
					return nil
				}
				return &fakeConnBackend{mode: bpf.BackendLegacy}
			}

			cfg := &config.Config{}
			cfg.Detection.PlacementBackend = tc.setting
			ch := make(chan alert.Finding, 4)
			var b bpf.Backend
			warns := captureWarnings(t, func() { b = StartPlacementMonitor(&FileMonitor{}, ch, cfg) })

			if tc.wantMode == "" {
				if b != nil {
					t.Fatalf("backend %q, want none", b.Mode())
				}
			} else if b == nil || b.Mode() != tc.wantMode {
				t.Fatalf("backend %#v, want mode %q", b, tc.wantMode)
			}
			if got := bpf.ActiveKind("placement"); got != tc.wantKind {
				t.Errorf("active kind %q, want %q", got, tc.wantKind)
			}
			if tries != tc.wantTries {
				t.Errorf("starters ran %q, want %q", tries, tc.wantTries)
			}
			if len(warns) != tc.wantWarns {
				t.Errorf("warnings %q, want %d", warns, tc.wantWarns)
			}
			if tc.wantKind == bpf.BackendNone && tc.wantWarns > 0 && !strings.Contains(warns[len(warns)-1], "renamed or hard-linked") {
				t.Errorf("none warning %q does not name what is not seen", warns[len(warns)-1])
			}
			var found []alert.Finding
			for len(ch) > 0 {
				found = append(found, <-ch)
			}
			if tc.wantFound == "" {
				if len(found) != 0 {
					t.Fatalf("unexpected findings %+v", found)
				}
				return
			}
			if len(found) != 1 || found[0].Check != "bpf_unavailable" || found[0].Severity != tc.wantSev ||
				!strings.Contains(found[0].Message, "for placement ") || !strings.Contains(found[0].Message, tc.wantFound) {
				t.Fatalf("findings %+v, want one bpf_unavailable %q", found, tc.wantFound)
			}
		})
	}
}
