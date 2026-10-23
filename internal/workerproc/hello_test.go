package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

var helloLimits = Limits{MaxFrameBytes: 1 << 10, MaxFDs: 1}

// helloPeer runs h on the far end of a socket pair and returns the near end.
func helloPeer(t *testing.T, h Handler) *net.UnixConn {
	t.Helper()
	a, b := socketPair(t)
	go func() { _ = Serve(context.Background(), b, helloLimits, h) }()
	return a
}

func answerProtocol(n int) Handler {
	return func(context.Context, Frame, []*os.File) (Frame, []*os.File) { return HelloReply(n), nil }
}

func TestHandshakeAcceptsMatchingProtocol(t *testing.T) {
	conn := helloPeer(t, func(_ context.Context, req Frame, _ []*os.File) (Frame, []*os.File) {
		var h Hello
		if req.Op != OpHello || json.Unmarshal(req.Payload, &h) != nil || h.Protocol != 3 {
			return Frame{Error: "bad hello"}, nil
		}
		return HelloReply(3), nil
	})
	if err := Handshake(context.Background(), conn, helloLimits, 3); err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeRejectsMismatch(t *testing.T) {
	conn := helloPeer(t, answerProtocol(2))
	err := Handshake(context.Background(), conn, helloLimits, 3)
	if err == nil || !strings.Contains(err.Error(), "protocol 2, want 3") {
		t.Fatalf("Handshake = %v", err)
	}
}

func TestHandshakeRejectsDescriptorsAndErrors(t *testing.T) {
	t.Run("descriptor", func(t *testing.T) {
		conn := helloPeer(t, func(context.Context, Frame, []*os.File) (Frame, []*os.File) {
			r, w, err := os.Pipe()
			if err != nil {
				return Frame{Error: err.Error()}, nil
			}
			_ = w.Close()
			return HelloReply(1), []*os.File{r}
		})
		before := openFDs(t)
		if err := Handshake(context.Background(), conn, helloLimits, 1); err == nil {
			t.Fatal("hello reply with a descriptor accepted")
		}
		assertNoFDLeak(t, before)
	})
	t.Run("error", func(t *testing.T) {
		conn := helloPeer(t, func(context.Context, Frame, []*os.File) (Frame, []*os.File) {
			return Frame{Error: "no"}, nil
		})
		if err := Handshake(context.Background(), conn, helloLimits, 1); err == nil {
			t.Fatal("hello Error reply accepted")
		}
	})
}

func TestHandshakeHonorsDeadline(t *testing.T) {
	a, b := socketPair(t)
	go func() { _, fds, _ := ReceiveFrame(b, helloLimits); closeFiles(fds) }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := Handshake(ctx, a, helloLimits, 1); err == nil {
		t.Fatal("silent worker passed the handshake")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("handshake took %s", took)
	}
}

func TestHandshakeHonorsCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%t", deadline), func(t *testing.T) {
			a, b := socketPair(t)
			ctx := context.Background()
			if deadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Minute)
				defer cancel()
			}
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- Handshake(ctx, a, helloLimits, 1) }()
			if _, fds, err := ReceiveFrame(b, helloLimits); err != nil {
				closeFiles(fds)
				t.Fatal(err)
			} else {
				closeFiles(fds)
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Handshake = %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				_ = a.Close()
				<-done
				t.Fatal("canceled handshake kept waiting for the worker")
			}
			// The cancellation callback must not leave a deadline behind.
			// Both directions need clearing even when the read was interrupted.
			for _, pair := range [][2]*net.UnixConn{{a, b}, {b, a}} {
				if err := SendFrame(pair[0], HelloReply(1), nil, helloLimits.MaxFrameBytes); err != nil {
					t.Fatalf("write after cancellation: %v", err)
				}
				_, fds, err := ReceiveFrame(pair[1], helloLimits)
				closeFiles(fds)
				if err != nil {
					t.Fatalf("read after cancellation: %v", err)
				}
			}
		})
	}
}

func TestHandshakeClearsDeadline(t *testing.T) {
	for _, protocol := range []int{1, 2} {
		t.Run(fmt.Sprintf("protocol=%d", protocol), func(t *testing.T) {
			conn := helloPeer(t, answerProtocol(protocol))
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			err := Handshake(ctx, conn, helloLimits, 1)
			if (err == nil) != (protocol == 1) {
				t.Fatalf("Handshake = %v", err)
			}
			<-ctx.Done()
			if err := Handshake(context.Background(), conn, helloLimits, protocol); err != nil {
				t.Fatalf("handshake left an expired deadline: %v", err)
			}
		})
	}
}
