//go:build !(linux && bpf)

package bpf

import "testing"

func TestProbeReturnsZeroOnNonBPFBuild(t *testing.T) {
	caps := Probe()
	if caps.LSMAttach || caps.CgroupSock || caps.Tracepoint || caps.Ringbuf {
		t.Fatalf("Probe on non-bpf build returned non-zero caps: %+v", caps)
	}
}
