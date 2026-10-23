package workerproc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
)

// Handler answers one request. It owns neither the request descriptors,
// which Serve closes after it returns, nor the reply descriptors, which
// Serve closes after sending them.
type Handler func(ctx context.Context, req Frame, fds []*os.File) (Frame, []*os.File)

// Serve answers request frames on conn until the parent closes it. It checks
// ctx between frames, not from inside the handler; the parent process remains
// the sole liveness boundary. It is the whole worker loop: one request at a
// time, no concurrency, no state carried between requests.
//
// A reply never carries an op: the parent matches replies by order on a
// single-flight connection, and echoing the op would invite a reader to match
// on it instead. Broken framing ends the loop because a trustworthy boundary
// for the next request no longer exists.
func Serve(ctx context.Context, conn *net.UnixConn, lim Limits, h Handler) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, fds, err := ReceiveFrame(conn, lim)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		resp, respFDs := h(ctx, req, fds)
		closeFiles(fds)
		resp.Op = ""
		err = SendFrame(conn, resp, respFDs, lim.MaxFrameBytes)
		closeFiles(respFDs)
		if err != nil {
			return err
		}
	}
}

// ChildConn returns the connection a launcher handed this worker on fd 0.
// A worker started by hand has a terminal or a pipe there, and reading frames
// from it would only produce garbage, so anything but a socket is refused.
func ChildConn() (*net.UnixConn, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(0, &st); err != nil {
		return nil, fmt.Errorf("workerproc: fd 0: %w", err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return nil, errors.New("workerproc: fd 0 is not a socket; workers are started by the daemon")
	}
	c, err := net.FileConn(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("workerproc: fd 0: %w", err)
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		return nil, errors.New("workerproc: fd 0 is not a Unix socket")
	}
	return uc, nil
}
