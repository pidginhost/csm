package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/bpf"
	"github.com/pidginhost/csm/internal/config"
)

type liveFeature struct {
	name  string
	start func(chan<- alert.Finding, *config.Config) bpf.Backend
	set   func(*config.Config, string)
	try   *func(context.Context, chan<- alert.Finding, *config.Config) (bpf.Backend, error)
}

func liveFeatures() []liveFeature {
	return []liveFeature{
		{"connection_tracker", StartConnectionTracker,
			func(c *config.Config, v string) { c.Detection.ConnectionTrackerBackend = v }, &tryStartConnectionBPFFn},
		{"exec_monitor", StartExecMonitor,
			func(c *config.Config, v string) { c.Detection.ExecMonitorBackend = v }, &tryStartExecBPFFn},
		{"sensitive_files", func(ch chan<- alert.Finding, c *config.Config) bpf.Backend {
			return StartSensitiveFileMonitor(ch, c, nil)
		}, func(c *config.Config, v string) { c.Detection.SensitiveFilesBackend = v }, &tryStartSensitiveFileBPFFn},
	}
}

// Every live feature reports its chosen backend under its own name and warns
// with its own name when BPF cannot start.
func TestLiveBackendsReportTheirFeature(t *testing.T) {
	cases := []struct {
		setting    string
		bpfErr     error
		wantKind   string
		wantNotice string // empty: no bpf_unavailable finding
		wantSev    alert.Severity
	}{
		{"none", nil, bpf.BackendNone, "", 0},
		{"auto", nil, bpf.BackendBPF, "", 0},
		{"legacy", nil, bpf.BackendLegacy, "", 0},
		{"auto", bpf.ErrNotBuilt, bpf.BackendLegacy, "running on legacy fallback", alert.Warning},
		{"bpf", bpf.ErrUnsupported, bpf.BackendNone, "no live fallback active", alert.High},
		{" BPF ", bpf.ErrUnsupported, bpf.BackendNone, "no live fallback active", alert.High},
	}
	for _, feat := range liveFeatures() {
		for _, tc := range cases {
			t.Run(feat.name+"/"+tc.setting, func(t *testing.T) {
				old := *feat.try
				*feat.try = func(context.Context, chan<- alert.Finding, *config.Config) (bpf.Backend, error) {
					if tc.bpfErr != nil {
						return nil, tc.bpfErr
					}
					return &fakeConnBackend{mode: bpf.BackendBPF}, nil
				}
				t.Cleanup(func() { *feat.try = old })

				cfg := &config.Config{}
				feat.set(cfg, tc.setting)
				ch := make(chan alert.Finding, 2)
				feat.start(ch, cfg)

				if got := bpf.ActiveKind(feat.name); got != tc.wantKind {
					t.Errorf("active kind = %q, want %q", got, tc.wantKind)
				}
				var notices []alert.Finding
				for len(ch) > 0 {
					notices = append(notices, <-ch)
				}
				if tc.wantNotice == "" {
					if len(notices) != 0 {
						t.Fatalf("unexpected findings: %+v", notices)
					}
					return
				}
				if len(notices) != 1 {
					t.Fatalf("findings = %+v, want one bpf_unavailable", notices)
				}
				f := notices[0]
				if f.Check != "bpf_unavailable" || f.Severity != tc.wantSev ||
					!strings.Contains(f.Message, "for "+feat.name+" ") || !strings.Contains(f.Message, tc.wantNotice) ||
					f.Details != tc.bpfErr.Error() {
					t.Errorf("finding = %+v", f)
				}
			})
		}
	}
}

// A feature whose legacy backend cannot start runs nothing and says so; the
// legacy constructors of the polling features never return nil.
func TestLiveBackendWithoutLegacyPublishesNone(t *testing.T) {
	failBPF := func() (bpf.Backend, error) { return nil, bpf.ErrUnsupported }
	noLegacy := func() bpf.Backend { return nil }
	for _, choice := range []string{"auto", "legacy"} {
		t.Run(choice, func(t *testing.T) {
			bpf.SetActive("test_no_legacy", bpf.BackendLegacy)
			ch := make(chan alert.Finding, 2)
			if b := startLiveBackend("test_no_legacy", choice, ch, failBPF, noLegacy); b != nil {
				t.Fatalf("backend %q, want none", b.Mode())
			}
			if got := bpf.ActiveKind("test_no_legacy"); got != bpf.BackendNone {
				t.Errorf("active kind %q, want none", got)
			}
			var found []alert.Finding
			for len(ch) > 0 {
				found = append(found, <-ch)
			}
			if choice == "legacy" {
				if len(found) != 0 {
					t.Fatalf("legacy choice never tried BPF, got %+v", found)
				}
				return
			}
			if len(found) != 1 || found[0].Severity != alert.High || !strings.Contains(found[0].Message, "no live fallback active") {
				t.Fatalf("findings %+v, want one High with no fallback", found)
			}
		})
	}
	for _, feat := range liveFeatures() {
		cfg := &config.Config{}
		feat.set(cfg, bpf.BackendLegacy)
		if b := feat.start(make(chan alert.Finding, 2), cfg); b == nil || b.Mode() != bpf.BackendLegacy {
			t.Errorf("%s legacy backend = %#v, want a running poller", feat.name, b)
		}
	}
}
