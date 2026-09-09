//go:build linux && kernelintegration

package daemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/queuehealth"
)

func TestNotificationKernelQueuesExposePendingRecords(t *testing.T) {
	for _, name := range []string{"fanotify", "spool"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var queue *notificationQueue
				fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if queue != nil {
						_ = queue.close()
					} else {
						_ = unix.Close(fd)
					}
				}()
				dir := t.TempDir()
				if markErr := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_CLOSE_WRITE|unix.FAN_EVENT_ON_CHILD, -1, dir); markErr != nil {
					t.Fatal(markErr)
				}
				for i := range 4 {
					if writeErr := os.WriteFile(filepath.Join(dir, fmt.Sprintf("event-%d.php", i)), []byte("<?php return true;"), 0o600); writeErr != nil {
						t.Fatal(writeErr)
					}
				}
				pendingBytes, err := unix.IoctlGetInt(fd, unix.TIOCINQ)
				if err != nil || pendingBytes != 4*metadataSize {
					t.Fatalf("kernel did not retain four notifications: bytes=%d err=%v", pendingBytes, err)
				}
				var statuses func(time.Time) map[string]queuehealth.Status
				if name == "fanotify" {
					monitor := &FileMonitor{fd: fd, analyzerCh: make(chan fileEvent, 1)}
					monitor.initQueueHealth()
					queue = monitor.kernelQueue
					statuses = monitor.queueStatuses
				} else {
					watcher := &SpoolWatcher{fd: fd, scanCh: make(chan spoolEvent, 1)}
					watcher.initQueueHealth()
					queue = watcher.kernelQueue
					statuses = watcher.queueStatuses
				}
				got := statuses(time.Now())[name+".kernel"]
				if got.Depth != 4 || got.DepthUnavailable || !got.CapacityUnavailable || got.DroppedTotal != 0 || got.Status != "ok" {
					t.Fatalf("kernel backlog absent from health: %+v", got)
				}
				time.Sleep(61 * time.Second)
				got = statuses(time.Now())[name+".kernel"]
				if got.Depth != 4 || got.LagBasis != "consumer_progress" || got.LagSeconds != 61 || got.Reason != "consumer_stalled" || got.Status != "degraded" {
					t.Fatalf("unread kernel records did not report a stalled reader: %+v", got)
				}
				processed := 0
				n, err := queue.read(make([]byte, 4*metadataSize), func(data []byte) {
					for offset := 0; offset < len(data); offset += metadataSize {
						var event fanotifyEventMetadata
						if decodeErr := binary.Read(bytes.NewReader(data[offset:offset+metadataSize]), binary.NativeEndian, &event); decodeErr != nil {
							t.Fatal(decodeErr)
						}
						if event.Fd >= 0 {
							defer func(fd int) { _ = unix.Close(fd) }(int(event.Fd))
						}
						if event.Fd < 0 || event.EventLen != uint32(metadataSize) || event.Mask&unix.FAN_CLOSE_WRITE == 0 {
							t.Errorf("unexpected notification: %+v", event)
						}
						processed++
					}
				})
				if err != nil || n != 4*metadataSize || processed != 4 {
					t.Fatalf("kernel drain: bytes=%d records=%d err=%v", n, processed, err)
				}
				states := statuses(time.Now())
				got = states[name+".kernel"]
				reader := states[name+".reader"]
				if got.Depth != 0 || got.Status != "ok" || got.LagSeconds != 0 || reader.InFlight != 0 || reader.DroppedTotal != 0 {
					t.Fatalf("kernel drain did not recover both queues: kernel=%+v reader=%+v", got, reader)
				}
				for i := range 2 {
					if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("abandoned-%d.php", i)), []byte("<?php return true;"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := queue.close(); err != nil {
					t.Fatal(err)
				}
				got = statuses(time.Now())[name+".kernel"]
				if got.Depth != 0 || got.DroppedTotal != 2 || !got.DroppedLowerBound || got.DepthUnavailable {
					t.Fatalf("known unread kernel events disappeared at close: %+v", got)
				}
			})
		})
	}
}
