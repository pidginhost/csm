package hostfacts

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const controllerTimeout = 5 * time.Second

// Controller request errors. ErrControllerNotSent means no request byte left
// CSM; ErrControllerNoReply means a request was written and no complete
// reply came back, so its outcome is unknown. ErrControllerPeer also wraps
// ErrControllerNotSent.
var (
	ErrControllerNotSent = errors.New("request not sent to rspamd's controller")
	ErrControllerNoReply = errors.New("no complete reply from rspamd's controller")
	ErrControllerPeer    = fmt.Errorf("rspamd's controller socket is not served by rspamd: %w", ErrControllerNotSent)
)

// ControllerGet sends GET path to rspamd's controller over its private Unix
// socket and returns the body of an HTTP 200 reply of at most limit bytes.
// Errors are fixed text; they never repeat the reply.
func ControllerGet(ctx context.Context, socket, path string, limit int64, peer int) ([]byte, error) {
	status, body, err := ControllerDo(ctx, socket, peer, http.MethodGet, path, nil, nil, limit)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("rspamd's controller returned HTTP %d", status)
	}
	return body, nil
}

// ControllerDo sends one request to rspamd's controller over its private
// Unix socket and returns the reply status and a body of at most limit
// bytes. The socket must be served by uid peer (SO_PEERCRED), so a process
// squatting the path after a restart gets nothing. It sends no forwarded
// header, so rspamd treats the request as local root access, and never a
// password. Errors are fixed text; they never repeat the reply.
func ControllerDo(ctx context.Context, socket string, peer int, method, path string, hdr map[string]string, body []byte, limit int64) (int, []byte, error) {
	request, err := controllerRequest(method, path, hdr, body)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", ErrControllerNotSent, err)
	}
	ctx, cancel := context.WithTimeout(ctx, controllerTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: cannot connect to rspamd's controller socket", ErrControllerNotSent)
	}
	defer func() { _ = conn.Close() }()
	if peerUID(conn) != peer {
		return 0, nil, ErrControllerPeer
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if err = writeControllerRequest(conn, request); err != nil {
		return 0, nil, err
	}
	// Framing gets its own allowance, as for /ping.
	reply := &io.LimitedReader{R: conn, N: 2*limit + 1}
	reader := bufio.NewReader(reply)
	var resp *http.Response
	for {
		resp, err = http.ReadResponse(reader, nil)
		if err != nil {
			return 0, nil, fmt.Errorf("%w: invalid HTTP response", ErrControllerNoReply)
		}
		if resp.StatusCode >= http.StatusOK {
			break
		}
		_ = resp.Body.Close()
		if resp.StatusCode < http.StatusContinue || resp.StatusCode == http.StatusSwitchingProtocols {
			return 0, nil, fmt.Errorf("%w: unexpected HTTP status", ErrControllerNoReply)
		}
		// Informational responses do not settle a mutation's outcome. Keep
		// the same reader and byte budget until a final response arrives.
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	switch {
	case err != nil:
		return 0, nil, fmt.Errorf("%w: the reply could not be read", ErrControllerNoReply)
	case reply.N == 0 || int64(len(data)) > limit:
		return 0, nil, fmt.Errorf("%w: the reply is too large", ErrControllerNoReply)
	}
	return resp.StatusCode, data, nil
}

func writeControllerRequest(w io.Writer, request []byte) error {
	if n, err := w.Write(request); err != nil {
		if n == 0 {
			return fmt.Errorf("%w: cannot send the request", ErrControllerNotSent)
		}
		// A partial write is not safe to repeat: rspamd may have received
		// enough of the request to act before the connection failed.
		return fmt.Errorf("%w: cannot send the request", ErrControllerNoReply)
	}
	return nil
}

// controllerRequest builds the request bytes, refusing anything that could
// split into a second request or header.
func controllerRequest(method, path string, hdr map[string]string, body []byte) ([]byte, error) {
	plain := func(s string) bool {
		return !strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f })
	}
	if method != http.MethodPost && (method != http.MethodGet || len(body) != 0) {
		return nil, errors.New("unsupported method")
	}
	if !strings.HasPrefix(path, "/") || !plain(path) || strings.Contains(path, " ") {
		return nil, errors.New("controller path is not a plain absolute path")
	}
	var b strings.Builder
	b.WriteString(method + " " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n")
	names := make([]string, 0, len(hdr))
	for name := range hdr {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "" || strings.ContainsFunc(name, func(r rune) bool {
			return (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-'
		}) || !plain(hdr[name]) {
			return nil, errors.New("invalid request header")
		}
		switch strings.ToLower(name) {
		case "host", "connection", "content-length", "transfer-encoding",
			"x-forwarded-for", "x-real-ip", "forwarded", "password", "authorization", "proxy-authorization":
			return nil, errors.New("reserved request header")
		}
		b.WriteString(name + ": " + hdr[name] + "\r\n")
	}
	if method == http.MethodPost {
		b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}
	b.WriteString("\r\n")
	return append([]byte(b.String()), body...), nil
}
