package bpf

import "testing"

func TestBackendKinds(t *testing.T) {
	cases := map[string]string{
		"BackendAuto":   BackendAuto,
		"BackendBPF":    BackendBPF,
		"BackendLegacy": BackendLegacy,
		"BackendNone":   BackendNone,
	}
	want := map[string]string{
		"BackendAuto":   "auto",
		"BackendBPF":    "bpf",
		"BackendLegacy": "legacy",
		"BackendNone":   "none",
	}
	for name, got := range cases {
		if got != want[name] {
			t.Errorf("%s = %q, want %q", name, got, want[name])
		}
	}
}

func TestErrSentinels(t *testing.T) {
	if ErrNotBuilt == nil {
		t.Fatal("ErrNotBuilt is nil")
	}
	if ErrUnsupported == nil {
		t.Fatal("ErrUnsupported is nil")
	}
	if ErrNotBuilt == ErrUnsupported {
		t.Fatal("ErrNotBuilt and ErrUnsupported must be distinct")
	}
}

func TestMetricForRegistersOnce(t *testing.T) {
	a := MetricFor("af_alg")
	b := MetricFor("connection_tracker")
	if a != b {
		t.Fatal("MetricFor must return the same gauge across calls")
	}
}

func TestSetActiveSetsExactlyOneSeriesToOne(t *testing.T) {
	SetActive("af_alg", BackendBPF)
	g := MetricFor("af_alg")
	if got := g.With("af_alg", BackendBPF).Value(); got != 1 {
		t.Fatalf("af_alg/bpf = %v, want 1", got)
	}
	if got := g.With("af_alg", BackendLegacy).Value(); got != 0 {
		t.Fatalf("af_alg/legacy = %v, want 0", got)
	}
	if got := g.With("af_alg", BackendNone).Value(); got != 0 {
		t.Fatalf("af_alg/none = %v, want 0", got)
	}
}

func TestActiveKindTracksSetActive(t *testing.T) {
	if got := ActiveKind("never_set"); got != "" {
		t.Fatalf("ActiveKind on unset feature = %q, want \"\"", got)
	}
	SetActive("connection_tracker", BackendLegacy)
	if got := ActiveKind("connection_tracker"); got != BackendLegacy {
		t.Fatalf("ActiveKind = %q, want %q", got, BackendLegacy)
	}
	SetActive("connection_tracker", BackendBPF)
	if got := ActiveKind("connection_tracker"); got != BackendBPF {
		t.Fatalf("ActiveKind after re-set = %q, want %q", got, BackendBPF)
	}
}
