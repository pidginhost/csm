//go:build !(linux && bpf)

package bpf

// probeKernel is the no-tag stub. It returns zero-value Capabilities so that
// all coordinators on this build see "no BPF surface available" and pick the
// legacy backend.
func probeKernel() Capabilities { return Capabilities{} }
