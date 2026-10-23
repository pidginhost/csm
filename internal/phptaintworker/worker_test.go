package phptaintworker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/phptaintipc"
	"github.com/pidginhost/csm/internal/workerproc"
)

func socketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	syscall.CloseOnExec(fds[0])
	syscall.CloseOnExec(fds[1])
	conn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "socketpair")
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	a, b := conn(fds[0]), conn(fds[1])
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// serve runs the worker loop over a socket pair and returns the responses it
// wrote, so a test can drive it exactly as the supervisor does.
func serve(t *testing.T, requests ...workerproc.Frame) []workerproc.Frame {
	t.Helper()
	parent, child := socketPair(t)
	done := make(chan error, 1)
	go func() {
		err := Serve(context.Background(), child)
		_ = child.Close()
		done <- err
	}()
	for _, f := range requests {
		if err := workerproc.SendFrame(parent, f, nil, phptaintipc.MaxFrameBytes); err != nil {
			t.Fatalf("write request: %v", err)
		}
	}
	_ = parent.CloseWrite()
	var got []workerproc.Frame
	for {
		f, _, err := workerproc.ReceiveFrame(parent, workerproc.Limits{MaxFrameBytes: phptaintipc.MaxFrameBytes})
		if err != nil {
			break
		}
		got = append(got, f)
	}
	if err := <-done; err != nil && err != io.EOF {
		t.Fatalf("serve: %v", err)
	}
	return got
}

func TestWorkerAnalyzesAndReportsAFlow(t *testing.T) {
	req, err := phptaintipc.EncodePayload(phptaintipc.OpAnalyze,
		phptaintipc.AnalyzeArgs{Source: []byte("<?php $p = curl_exec($c); eval($p);")})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got := serve(t, req)
	if len(got) != 1 {
		t.Fatalf("responses = %d, want 1", len(got))
	}
	var res phptaintipc.AnalyzeResult
	if err := phptaintipc.DecodePayload(got[0], &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Report.Status != phptaint.StatusAnalyzed || len(res.Report.Results) != 1 {
		t.Fatalf("report = %+v, want one analyzed flow", res.Report)
	}
}

// TestWorkerServesMoreThanOneRequest pins that the process is long-lived. If it
// answered one request and exited, the supervisor would pay a fork+exec per
// candidate file, which is the design this worker exists to avoid.
func TestWorkerServesMoreThanOneRequest(t *testing.T) {
	req, _ := phptaintipc.EncodePayload(phptaintipc.OpAnalyze,
		phptaintipc.AnalyzeArgs{Source: []byte("<?php echo 1;")})
	got := serve(t, req, req, req)
	if len(got) != 3 {
		t.Fatalf("responses = %d, want 3", len(got))
	}
}

func TestWorkerAnswersPing(t *testing.T) {
	got := serve(t, workerproc.Frame{Op: phptaintipc.OpPing})
	if len(got) != 1 {
		t.Fatalf("responses = %d, want 1", len(got))
	}
	var res phptaintipc.PingResult
	if err := phptaintipc.DecodePayload(got[0], &res); err != nil {
		t.Fatalf("decode ping: %v", err)
	}
	if !res.OK {
		t.Fatal("ping not OK")
	}
}

// TestWorkerReportsUnknownOpWithoutExiting keeps a malformed request from
// killing a process the supervisor would then have to replace. An unknown op is
// the peer's mistake, not a reason to drop the worker.
func TestWorkerReportsUnknownOpWithoutExiting(t *testing.T) {
	follow, _ := phptaintipc.EncodePayload(phptaintipc.OpAnalyze,
		phptaintipc.AnalyzeArgs{Source: []byte("<?php echo 1;")})
	got := serve(t, workerproc.Frame{Op: "nonsense"}, follow)
	if len(got) != 2 {
		t.Fatalf("responses = %d, want 2 (error then a served request)", len(got))
	}
	if got[0].Error == "" || !strings.Contains(got[0].Error, "nonsense") {
		t.Fatalf("first response = %+v, want an error naming the op", got[0])
	}
	if got[1].Error != "" {
		t.Fatalf("worker did not recover after an unknown op: %+v", got[1])
	}
}

// TestWorkerReportsBadPayloadWithoutExiting is the same contract for a payload
// that decodes but violates the protocol's own validation.
func TestWorkerReportsBadPayloadWithoutExiting(t *testing.T) {
	bad := workerproc.Frame{Op: phptaintipc.OpAnalyze, Payload: json.RawMessage(`{"nope":1}`)}
	follow, _ := phptaintipc.EncodePayload(phptaintipc.OpAnalyze,
		phptaintipc.AnalyzeArgs{Source: []byte("<?php echo 1;")})
	got := serve(t, bad, follow)
	if len(got) != 2 || got[0].Error == "" || got[1].Error != "" {
		t.Fatalf("responses = %+v, want an error then a served request", got)
	}
}

// TestWorkerStopsOnContextCancel is what lets the supervisor shut a healthy
// worker down cleanly instead of killing it.
func TestWorkerStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	parent, child := socketPair(t)
	req, _ := phptaintipc.EncodePayload(phptaintipc.OpAnalyze,
		phptaintipc.AnalyzeArgs{Source: []byte("<?php echo 1;")})
	_ = workerproc.SendFrame(parent, req, nil, phptaintipc.MaxFrameBytes)
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, child) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return on a cancelled context")
	}
}

func TestWorkerRejectsTruncatedFrame(t *testing.T) {
	parent, child := socketPair(t)
	if _, err := parent.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	_ = parent.CloseWrite()
	err := Serve(context.Background(), child)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want io.ErrUnexpectedEOF", err)
	}
}
