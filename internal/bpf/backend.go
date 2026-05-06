// Package bpf provides the shared scaffolding that BPF-backed live monitors
// across the daemon use: a common Backend interface, backend-kind constants
// for operator config, sentinel errors that distinguish "not built" from
// "kernel unsupported", and a per-feature backend metric.
//
// Real BPF code (program loading, ringbuf consumption, capability probing)
// lives behind the linux && bpf build tag in sibling files. Default builds
// compile stubs that report all capabilities as unavailable.
package bpf

import (
	"context"
	"errors"
	"sync"

	"github.com/pidginhost/csm/internal/metrics"
)

// Backend is the shape every BPF-backed live monitor implements. The legacy
// fallback for each feature implements the same interface so the coordinator
// hands the daemon a uniform handle.
type Backend interface {
	Mode() string
	EventCount() uint64
	Run(ctx context.Context)
}

// Backend kind constants are the shared internal values used after each
// feature validates its operator-facing config setting. Individual features
// may keep older public values, such as AF_ALG's "auditd", and map them to
// BackendLegacy internally.
const (
	BackendAuto   = "auto"
	BackendBPF    = "bpf"
	BackendLegacy = "legacy"
	BackendNone   = "none"
)

// ErrNotBuilt is returned by feature loaders when CSM was built without the
// bpf build tag. The coordinator treats this identically to a kernel that
// lacks the required BPF program type: log it and fall back to legacy.
var ErrNotBuilt = errors.New("BPF support not compiled in (rebuild with -tags bpf)")

// ErrUnsupported is returned when CSM was built with the bpf tag but the
// running kernel does not accept the requested BPF program type. Distinct
// from ErrNotBuilt so operator logs explain whether the fix is "rebuild" or
// "newer kernel".
var ErrUnsupported = errors.New("kernel does not support requested BPF program type")

var (
	backendMetric     *metrics.GaugeVec
	backendMetricOnce sync.Once

	activeMu    sync.RWMutex
	activeKinds map[string]string
)

// MetricFor returns the shared csm_bpf_backend gauge. The feature argument
// is accepted for call-site readability; all features share a single
// GaugeVec distinguished by the label value, not by separate vec instances.
// Registered exactly once across the process. Pair with SetActive instead
// of calling With directly.
func MetricFor(_ string) *metrics.GaugeVec {
	backendMetricOnce.Do(func() {
		backendMetric = metrics.NewGaugeVec(
			"csm_bpf_backend",
			"Active backend for each BPF-backed live monitor; 1 for the selected kind, 0 otherwise.",
			[]string{"feature", "kind"},
		)
		metrics.MustRegister("csm_bpf_backend", backendMetric)
	})
	return backendMetric
}

// SetActive sets the metric series so that exactly one of {bpf, legacy, none}
// is at 1 and the others at 0 for the given feature. Call from the coordinator
// after backend selection. Also remembers the active kind in-process so
// internal/health can render the matching capability string without
// reaching into the metric registry.
func SetActive(feature, active string) {
	g := MetricFor(feature)
	for _, k := range []string{BackendBPF, BackendLegacy, BackendNone} {
		v := 0.0
		if k == active {
			v = 1.0
		}
		g.With(feature, k).Set(v)
	}
	activeMu.Lock()
	if activeKinds == nil {
		activeKinds = make(map[string]string)
	}
	activeKinds[feature] = active
	activeMu.Unlock()
}

// ActiveKind returns the kind currently selected for the given feature, or
// "" if SetActive was never called for it. internal/health uses this to
// render per-feature capability strings without importing the metrics
// registry.
func ActiveKind(feature string) string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeKinds[feature]
}
