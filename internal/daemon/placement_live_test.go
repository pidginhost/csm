package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

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
	noFID := fmt.Errorf("%w: fanotify_init: invalid argument", errPlacementFIDUnsupported)
	cases := []struct {
		name      string
		setting   string
		bpfErr    error
		fidErr    error
		wantMode  string
		wantKind  string
		wantFound string // bpf_unavailable message part; empty: no finding
		wantSev   alert.Severity
		wantWarns int
		wantTries string // which starters ran, in order
	}{
		{"auto with BPF", "auto", nil, nil, "bpf", bpf.BackendBPF, "", 0, 0, "b"},
		{"auto falls back to fanotify", "", bpf.ErrUnsupported, nil, "legacy", bpf.BackendLegacy, "running on legacy fallback", alert.Warning, 0, "bf"},
		{"auto on a kernel with neither", "auto", bpf.ErrUnsupported, noFID, "", bpf.BackendNone, "", 0, 1, "bf"},
		{"auto without the bpf build or fanotify", "auto", bpf.ErrNotBuilt, noFID, "", bpf.BackendNone, "", 0, 1, "bf"},
		{"auto with an unexpected fanotify error", "auto", bpf.ErrUnsupported, unix.EPERM, "", bpf.BackendNone, "no live fallback active", alert.High, 1, "bf"},
		{"auto with an unexpected BPF error", "auto", errors.New("load BPF objects: verifier rejected"), noFID, "", bpf.BackendNone, "no live fallback active", alert.High, 1, "bf"},
		{"none", "none", nil, nil, "", bpf.BackendNone, "", 0, 1, ""},
		{"legacy pins fanotify", "legacy", nil, nil, "legacy", bpf.BackendLegacy, "", 0, 0, "f"},
		{"legacy without fanotify", "legacy", nil, noFID, "", bpf.BackendNone, "", 0, 1, "f"},
		{"bpf strict never falls back", " BPF ", bpf.ErrUnsupported, nil, "", bpf.BackendNone, "no live fallback active", alert.High, 1, "b"},
		{"unknown value runs auto", "potato", nil, nil, "bpf", bpf.BackendBPF, "", 0, 1, "b"},
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
			tryStartPlacementFIDFn = func(context.Context, *FileMonitor) (bpf.Backend, error) {
				tries += "f"
				if tc.fidErr != nil {
					return nil, tc.fidErr
				}
				return &fakeConnBackend{mode: bpf.BackendLegacy}, nil
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
			if tc.wantKind == bpf.BackendNone && strings.TrimSpace(strings.ToLower(tc.setting)) != "bpf" && !strings.Contains(warns[len(warns)-1], "renamed or hard-linked") {
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
				!strings.Contains(found[0].Message, "for placement ") || !strings.Contains(found[0].Message, tc.wantFound) ||
				!strings.Contains(found[0].Details, tc.bpfErr.Error()) {
				t.Fatalf("findings %+v, want one bpf_unavailable %q naming the BPF error", found, tc.wantFound)
			}
			if tc.fidErr != nil && !strings.Contains(found[0].Details, tc.fidErr.Error()) {
				t.Errorf("finding details %q do not name the fanotify error", found[0].Details)
			}
		})
	}
}
