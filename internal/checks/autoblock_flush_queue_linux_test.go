//go:build linux

package checks

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"golang.org/x/sys/unix"
)

type flushQueueReadSwap struct {
	OS
	path string
	read chan struct{}
}

func (r flushQueueReadSwap) ReadFile(path string) ([]byte, error) {
	data, err := r.OS.ReadFile(path)
	if path != r.path || err != nil {
		return data, err
	}
	if err = os.Rename(path, path+".saved"); err != nil {
		return nil, err
	}
	if err = os.Mkdir(path, 0700); err != nil {
		return nil, err
	}
	close(r.read)
	return data, nil
}

// The flush's first failure is the real final rename, after a successful tracker
// read. Its error must be visible while the existing error log blocks, before
// the flush can return its error to the operator.
func TestAutoBlockQueueFlushWriteErrorBeforeBlockedLog(t *testing.T) {
	cfg := autoBlockQueueFixture(t, func() error { return nil })
	writeFirewallFlushState(t, cfg.StatePath, "192.0.2.40")
	path := filepath.Join(cfg.StatePath, blockStateFile)
	if err := writeBlockState(cfg.StatePath, &blockState{IPs: []blockedIP{{IP: "192.0.2.40", Reason: "earlier", ExpiresAt: time.Now().Add(time.Hour)}}}); err != nil {
		t.Fatal(err)
	}
	previousOS := osFS
	read := make(chan struct{})
	osFS = flushQueueReadSwap{OS: realOS{}, path: path, read: read}
	defer func() { osFS = previousOS }()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := int(writer.Fd())
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	for {
		_, err := unix.Write(fd, bytes.Repeat([]byte{'x'}, 4096))
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	previousStderr := os.Stderr
	os.Stderr = writer
	defer func() { os.Stderr = previousStderr }()
	type outcome struct {
		result AutoBlockFlushResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := FlushAutoBlockState(cfg.StatePath, func() error { return nil })
		done <- outcome{result, err}
	}()
	defer func() {
		var output bytes.Buffer
		drained := make(chan struct{})
		go func() { _, _ = io.Copy(&output, reader); close(drained) }()
		select {
		case got := <-done:
			if !got.result.Flushed || got.result.SnapshotErr != nil || got.result.BlockedCount != 1 || got.err == nil || !strings.Contains(got.err.Error(), "rename:") {
				t.Errorf("flush result changed: %+v error=%v", got.result, got.err)
			}
			assertAutoBlockQueueDrained(t, 1)
		case <-time.After(3 * time.Second):
			t.Error("flush did not join after draining log")
		}
		_ = writer.Close()
		<-drained
		if strings.Count(output.String(), "autoblock: persist ") != 1 {
			t.Error("expected exactly one existing persistence error log")
		}
		data, err := os.ReadFile(path + ".saved")
		if err != nil {
			t.Error(err)
		} else if !strings.Contains(string(data), "192.0.2.40") {
			t.Error("original tracker evidence missing")
		}
	}()
	select {
	case <-read:
	case <-time.After(3 * time.Second):
		t.Fatal("successful tracker read not reached")
	}
	// Require the actual flush to be blocked in its diagnostic,
	// instead of inferring the failure from elapsed time after the read hook.
	deadline := time.Now().Add(3 * time.Second)
	for {
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		blocked := false
		for _, g := range strings.Split(string(stack[:n]), "\n\n") {
			if strings.Contains(g, ".FlushAutoBlockState(") && strings.Contains(g, "internal/poll.(*FD).Write(") {
				blocked = true
				break
			}
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed write did not reach blocked diagnostic")
		}
		time.Sleep(time.Millisecond)
	}
	row := AutoBlockQueueStatuses(time.Now())["active"]
	if row.InFlight != 1 || row.DroppedTotal != 1 {
		t.Errorf("known flush write error hidden during log cleanup: in_flight=%d loss=%d, want1/1", row.InFlight, row.DroppedTotal)
	}
}

// A direct caller captures its engine before admission; scans capture theirs
// after admission. Replacing the global while both wait must preserve that
// existing distinction and cannot make reentrant health calls wait for state.
type captureQueueBlocker struct{ admissionBlocker }

func (captureQueueBlocker) IsBlocked(ip string) bool { return ip == "192.0.2.11" }

func TestAutoBlockQueueWaitingEngineCapture(t *testing.T) {
	var oldCalls, newCalls atomic.Int32
	inspect := func(counter *atomic.Int32) error {
		counter.Add(1)
		row := AutoBlockQueueStatuses(time.Now())["active"]
		if row.InFlight != 1 || row.Capacity != 1 {
			t.Errorf("callback missing actual owner: %+v", row)
		}
		return nil
	}
	cfg := autoBlockQueueFixture(t, func() error { return inspect(&oldCalls) })
	blockStateMu.Lock()
	locked := true
	done := make(chan error, 2)
	remaining := 2
	defer func() {
		if locked {
			blockStateMu.Unlock()
		}
		for remaining > 0 {
			select {
			case <-done:
				remaining--
			case <-time.After(3 * time.Second):
				t.Error("admission callers did not join")
				return
			}
		}
	}()
	go func() { done <- autoBlockQueueCall(cfg, "direct", nil) }()
	waitAutoBlockQueue(t, 1, 0)
	SetIPBlocker(captureQueueBlocker{admissionBlocker{call: func() error { return inspect(&newCalls) }}})
	go func() {
		findings := AutoBlockIPs(cfg, []alert.Finding{{Check: "wp_login_bruteforce", SourceIP: "192.0.2.41", Message: "new engine", Severity: alert.Critical}})
		if len(findings) != 1 || findings[0].SourceIP != "192.0.2.41" {
			t.Errorf("scan findings changed: count=%d", len(findings))
		}
		done <- nil
	}()
	waitAutoBlockQueue(t, 2, 0)
	blockStateMu.Unlock()
	locked = false
	for remaining > 0 {
		select {
		case err := <-done:
			remaining--
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("queued caller stayed blocked")
		}
	}
	if oldCalls.Load() != 1 || newCalls.Load() != 1 {
		t.Errorf("engine capture changed: old=%d new=%d", oldCalls.Load(), newCalls.Load())
	}
	state, err := readBlockState(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.IPs) != 2 || state.BlocksThisHour != 1 {
		t.Errorf("serialized evidence changed: ips=%d quota=%d", len(state.IPs), state.BlocksThisHour)
	}
	assertAutoBlockQueueDrained(t, 0)
}
