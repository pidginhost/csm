package hostfacts

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const controllerTimeout = 5 * time.Second

// ControllerGet sends GET path to rspamd's controller over its private Unix
// socket and returns the body of an HTTP 200 reply of at most limit bytes.
// It sends no forwarded header, so rspamd treats the request as local root
// access, and never a password. Errors are fixed text; they never repeat the
// reply.
func ControllerGet(ctx context.Context, socket, path string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsFunc(path, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return nil, errors.New("controller path is not a plain absolute path")
	}
	ctx, cancel := context.WithTimeout(ctx, controllerTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, errors.New("cannot connect to rspamd's controller socket")
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if _, err = io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
		return nil, errors.New("cannot send a request to rspamd's controller")
	}
	// Framing gets its own allowance, as for /ping.
	reply := &io.LimitedReader{R: conn, N: 2*limit + 1}
	resp, err := http.ReadResponse(bufio.NewReader(reply), nil)
	if err != nil {
		return nil, errors.New("rspamd's controller returned an invalid HTTP response")
	}
	defer func() {
		_ = conn.Close()
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	switch {
	case err != nil:
		return nil, errors.New("rspamd's controller reply could not be read")
	case reply.N == 0 || int64(len(body)) > limit:
		return nil, errors.New("rspamd's controller reply is too large")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("rspamd's controller returned HTTP %d", resp.StatusCode)
	}
	return body, nil
}
