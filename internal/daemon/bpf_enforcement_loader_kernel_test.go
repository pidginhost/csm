//go:build linux && bpf && kernelintegration

package daemon

import (
	"maps"
	"testing"

	"github.com/cilium/ebpf"
)

func TestKernelInstallSafeUIDsRemovesStaleHostedUIDs(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16})
	if err != nil {
		t.Fatalf("create safe_uids map: %v", err)
	}
	defer func() { _ = m.Close() }()
	if err := installSafeUIDs(m, map[uint32]bool{0: true, 89: true, 1005: true, 1006: true}); err != nil {
		t.Fatal(err)
	}
	// 89 left /etc/passwd and 1006 was deleted or reassigned.
	if err := installSafeUIDs(m, map[uint32]bool{0: true, 1005: true}); err != nil {
		t.Fatal(err)
	}
	got := map[uint32]bool{}
	var uid uint32
	var v uint8
	it := m.Iterate()
	for it.Next(&uid, &v) {
		got[uid] = true
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	if want := map[uint32]bool{0: true, 89: true, 1005: true}; !maps.Equal(got, want) {
		t.Fatalf("safe_uids = %v, want %v", got, want)
	}
}
