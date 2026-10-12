package hostfacts

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/antispam"
)

// Probe limits from spec section 7.
const (
	pingTimeout = 3 * time.Second
	maxPingBody = 4 << 10
	// Framing has its own allowance so headers and chunk metadata cannot
	// consume unbounded memory before the decoded body limit applies.
	maxPingReply = 2 * maxPingBody
)

// Ping sends GET /ping over the rspamd socket and wants HTTP 200 with "pong"
// (rspamd ends it with CRLF). It returns the listener's uid from SO_PEERCRED,
// or -1 when no connection was made; the uid stays known when the reply is
// wrong. Errors never repeat the reply.
func Ping(ctx context.Context, socket string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return -1, err
	}
	defer func() { _ = conn.Close() }()
	uid := peerUID(conn)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	// Install cancellation last so an expired deadline cannot be replaced
	// by the later timeout when the caller cancels during setup.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if _, err = io.WriteString(conn, "GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
		return uid, err
	}
	return uid, readPingReply(conn)
}

func readPingReply(conn io.ReadCloser) error {
	reply := &io.LimitedReader{R: conn, N: maxPingReply + 1}
	resp, err := http.ReadResponse(bufio.NewReader(reply), nil)
	if err != nil {
		return errors.New("rspamd /ping returned an invalid HTTP response")
	}
	defer func() {
		// ReadResponse bodies can drain unread data on Close. This probe
		// never reuses its connection, so close it before closing the body.
		_ = conn.Close()
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPingBody+1))
	switch {
	case err != nil:
		return errors.New("rspamd /ping reply could not be read")
	case reply.N == 0:
		return errors.New("rspamd /ping reply is too large")
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("rspamd /ping returned HTTP %d", resp.StatusCode)
	case len(body) > maxPingBody:
		return errors.New("rspamd /ping reply is too large")
	case strings.Trim(string(body), " \t\r\n") != "pong":
		return errors.New("rspamd /ping did not answer pong")
	}
	return nil
}

// socketFacts describes the scan socket, the directories its path walks
// through and one /ping. The caller fills the uids it knows.
func socketFacts(ctx context.Context, socket string) antispam.SocketFacts {
	f := antispam.SocketFacts{Socket: antispam.PathFacts{Path: socket}, RspamdUID: -1, PeerUID: -1, EximUID: -1, EximGID: -1}
	if err := antispam.ValidateSocket(socket); err != nil {
		f.Err = err
		return f
	}
	final, dirs, walkErr := resolve(socket)
	for _, d := range dirs {
		facts, err := pathFacts(d)
		if err != nil {
			f.Err = err
			return f
		}
		f.Parents = append(f.Parents, facts)
	}
	switch {
	case errors.Is(walkErr, fs.ErrNotExist):
		f.Missing = true
		return f
	case walkErr != nil:
		f.Err = walkErr
		return f
	}
	facts, err := pathFacts(final)
	if err != nil {
		f.Err = err
		return f
	}
	f.Socket = facts
	f.PeerUID, f.PingErr = Ping(ctx, socket)
	return f
}
