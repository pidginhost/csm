package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func echoHandler(_ context.Context, req Frame, _ []*os.File) (Frame, []*os.File) {
	return Frame{Payload: req.Payload}, nil
}

func TestServeAnswersInOrder(t *testing.T) {
	parent, child := socketPair(t)
	lim := Limits{MaxFrameBytes: 1 << 20}
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), child, lim, echoHandler) }()
	for _, p := range []string{"1", "2", "3"} {
		if err := SendFrame(parent, Frame{Op: "x", Payload: json.RawMessage(p)}, nil, 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"1", "2", "3"} {
		f, _, err := ReceiveFrame(parent, lim)
		if err != nil || string(f.Payload) != want {
			t.Fatalf("reply = %+v err=%v, want payload %s", f, err, want)
		}
	}
	_ = parent.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestServeEndsOnEOF(t *testing.T) {
	parent, child := socketPair(t)
	_ = parent.Close()
	if err := Serve(context.Background(), child, Limits{MaxFrameBytes: 1 << 20}, echoHandler); err != nil {
		t.Fatalf("Serve on EOF = %v, want nil", err)
	}
}

func TestServeRejectsTruncatedFrame(t *testing.T) {
	parent, child := socketPair(t)
	if _, err := parent.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	_ = parent.CloseWrite()
	err := Serve(context.Background(), child, Limits{MaxFrameBytes: 1 << 20}, echoHandler)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestServeStopsOnContextCancel(t *testing.T) {
	parent, child := socketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := SendFrame(parent, Frame{Op: "x"}, nil, 1<<20); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, child, Limits{MaxFrameBytes: 1 << 20}, echoHandler) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return on a cancelled context")
	}
}

func TestServeClearsReplyOpAndClosesDescriptors(t *testing.T) {
	parent, child := socketPair(t)
	before := openFDs(t)
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), child, Limits{MaxFrameBytes: 1 << 20, MaxFDs: 1},
			func(_ context.Context, req Frame, fds []*os.File) (Frame, []*os.File) {
				r, w, err := os.Pipe()
				if err != nil {
					return Frame{Error: err.Error()}, nil
				}
				_ = w.Close()
				return Frame{Op: "echoed", Payload: req.Payload}, []*os.File{r}
			})
	}()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if sendErr := SendFrame(parent, Frame{Op: "x", Payload: json.RawMessage(`1`)}, []*os.File{w}, 1<<20); sendErr != nil {
		t.Fatal(sendErr)
	}
	_ = r.Close()
	_ = w.Close()
	f, fds, err := ReceiveFrame(parent, Limits{MaxFrameBytes: 1 << 20, MaxFDs: 1})
	if err != nil || f.Op != "" || string(f.Payload) != "1" || len(fds) != 1 {
		t.Fatalf("reply=%+v fds=%d err=%v", f, len(fds), err)
	}
	_ = fds[0].Close()
	_ = parent.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assertNoFDLeak(t, before)
}

func TestChildConnRejectsNonSocket(t *testing.T) {
	if os.Getenv("CSM_WORKERPROC_CHILDCONN") == "1" {
		if _, err := ChildConn(); err == nil || !strings.Contains(err.Error(), "not a socket") {
			os.Exit(2)
		}
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestChildConnRejectsNonSocket")
	cmd.Env = append(os.Environ(), "CSM_WORKERPROC_CHILDCONN=1")
	cmd.Stdin = strings.NewReader("") // a pipe, not a socket
	if err := cmd.Run(); err != nil {
		t.Fatalf("ChildConn on a pipe: %v", err)
	}
}
