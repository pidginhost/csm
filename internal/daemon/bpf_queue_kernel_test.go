//go:build linux && bpf && kernelintegration

package daemon

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/pidginhost/csm/internal/bpf"
	bpfprog "github.com/pidginhost/csm/internal/daemon/connection_bpfprog"
	"golang.org/x/sys/unix"
)

// This runs the shipped connection program with a smaller ring and a real
// non-root syscall producer. A stopped reader must count every failed reserve
// and every submitted event that shutdown leaves unconsumed.
func TestKernelConnectionQueueLoss(t *testing.T) {
	const attempts = 128
	if os.Getenv("CSM_BPF_QUEUE_PRODUCER") == "1" {
		if os.Geteuid() != 1001 {
			t.Fatalf("producer UID = %d, want 1001", os.Geteuid())
		}
		for range attempts {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
			if err != nil {
				t.Fatal(err)
			}
			err = unix.Connect(fd, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}})
			closeErr := unix.Close(fd)
			if err != nil && err != unix.EINPROGRESS && err != unix.ECONNREFUSED {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
		}
		return
	}
	spec, err := bpfprog.LoadConnection()
	if err != nil {
		t.Fatal(err)
	}
	spec.Maps["events"].MaxEntries = 4096
	var objects bpfprog.ConnectionObjects
	if err = spec.LoadAndAssign(&objects, nil); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := objects.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}()
	cgroup, err := unifiedCgroupRoot()
	if err != nil {
		t.Fatal(err)
	}
	attachment, err := link.AttachCgroup(link.CgroupOptions{Path: cgroup, Attach: ebpf.AttachCGroupInet4Connect, Program: objects.CsmConnect4})
	if err != nil {
		t.Fatal(err)
	}
	attached := true
	defer func() {
		if attached {
			_ = attachment.Close()
		}
	}()
	reader, err := bpf.NewReader(objects.Events, objects.QueueStats, decodeConnectionEvent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// An inherited descriptor permits executing this test binary without
	// granting the child traversal of the root-owned Go build directories.
	producer := exec.CommandContext(ctx, "/proc/self/fd/3", "-test.run=^TestKernelConnectionQueueLoss$", "-test.count=1")
	producer.ExtraFiles = []*os.File{file}
	producer.Env = []string{"CSM_BPF_QUEUE_PRODUCER=1"}
	producer.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1001, Gid: 1001}}
	if output, err := producer.CombinedOutput(); err != nil {
		t.Fatalf("kernel event producer: %v\n%s", err, output)
	}
	if err := attachment.Close(); err != nil {
		t.Fatal(err)
	}
	attached = false
	var counts struct{ Lost, Submitted uint64 }
	if err := objects.QueueStats.Lookup(uint32(0), &counts); err != nil {
		t.Fatal(err)
	}
	// Each event occupies 56 payload bytes and an 8-byte ring header. The
	// producer position must stay below the 4096-byte consumer window.
	if counts.Submitted != 63 || counts.Lost != attempts-63 {
		t.Fatalf("kernel reserve accounting = %+v, want submitted=63 lost=65", counts)
	}
	before := reader.QueueStatuses(time.Now())["kernel"]
	if before.Depth != 4032 || before.Capacity != 4096 || before.DepthUnit != "bytes" || before.DroppedTotal != 65 || before.Reason != "dropped_work" {
		t.Fatalf("real ring pressure missing from status: %+v", before)
	}
	// Close before starting so no record can escape to userspace. Start's
	// stop function still joins and performs the normal final accounting.
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	stop := reader.Start(context.Background())
	stop()
	after := reader.QueueStatuses(time.Now())["kernel"]
	if after.Depth != 0 || after.DepthUnavailable || after.DroppedTotal != attempts || after.RecentDrops != attempts {
		t.Fatalf("kernel shutdown failed to count all %d events exactly once: %+v", attempts, after)
	}
}
