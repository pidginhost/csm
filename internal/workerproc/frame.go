// Package workerproc runs CSM's out-of-process workers: code that parses
// attacker-controlled input and can loop, crash or exhaust memory, so the
// daemon runs it in a child process it can kill.
//
// Daemon and worker share one Unix stream socket. A frame is a 4-byte
// big-endian length followed by a JSON envelope, and may carry descriptors
// with SCM_RIGHTS. The length prefix comes from the peer and is checked
// against a cap before any buffer is allocated.
package workerproc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxSendFDs is the kernel's SCM_MAX_FD: the most descriptors one sendmsg
// can carry.
const maxSendFDs = 253

// Frame is the envelope. A request carries an Op and a typed Payload; a
// response leaves Op empty and carries either a Payload or an Error.
type Frame struct {
	Op      string          `json:"op,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// Limits bounds what one received frame may carry. MaxFrameBytes caps the
// body; MaxFDs caps descriptors, and 0 accepts none.
type Limits struct {
	MaxFrameBytes int
	MaxFDs        int
}

// WriteFrame writes one length-prefixed frame.
func WriteFrame(w io.Writer, f Frame, maxBytes int) error {
	body, err := marshalBody(f, maxBytes)
	if err != nil {
		return err
	}
	if err := writeFull(w, withHeader(body)); err != nil {
		return fmt.Errorf("workerproc: write frame: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed frame.
//
// The length prefix comes from the peer, so it is checked against the cap
// BEFORE any buffer is allocated. Reading the declared size first and
// validating afterwards would let a four-byte write ask for gigabytes.
func ReadFrame(r io.Reader, maxBytes int) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, fmt.Errorf("workerproc: read header: %w", err)
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if int64(size) > int64(maxBytes) {
		return Frame{}, fmt.Errorf("workerproc: declared frame size %d exceeds cap %d", size, maxBytes)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		if errors.Is(err, io.EOF) {
			// Only an end before the header is a clean end of stream.
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, fmt.Errorf("workerproc: read body: %w", err)
	}
	var f Frame
	if err := json.Unmarshal(body, &f); err != nil {
		return Frame{}, fmt.Errorf("workerproc: unmarshal frame: %w", err)
	}
	return f, nil
}

// SendFrame writes one frame to conn with fds attached. The caller keeps
// ownership of fds.
func SendFrame(conn *net.UnixConn, f Frame, fds []*os.File, maxBytes int) error {
	body, err := marshalBody(f, maxBytes)
	if err != nil {
		return err
	}
	return sendBody(conn, body, fds)
}

// sendBody sends an already marshalled, already capped body.
func sendBody(conn *net.UnixConn, body []byte, fds []*os.File) error {
	if len(fds) > maxSendFDs {
		return fmt.Errorf("workerproc: %d descriptors exceed the kernel limit of %d", len(fds), maxSendFDs)
	}
	buf := withHeader(body)
	var oob []byte
	if len(fds) > 0 {
		raw := make([]int, len(fds))
		for i, f := range fds {
			raw[i] = int(f.Fd())
		}
		oob = syscall.UnixRights(raw...)
	}
	// WriteMsgUnix is a single sendmsg, which a stream socket may cut short
	// once its buffer fills. The descriptors went with the first byte; the
	// rest of the frame follows as plain writes.
	n, _, err := conn.WriteMsgUnix(buf, oob, nil)
	runtime.KeepAlive(fds)
	if err == nil && n < len(buf) {
		err = writeFull(conn, buf[n:])
	}
	if err != nil {
		return fmt.Errorf("workerproc: send frame: %w", err)
	}
	return nil
}

// ReceiveFrame reads one frame from conn with any descriptors that came with
// it. On error every received descriptor is closed; on success the caller
// owns the returned files. After an error the connection must be closed:
// unread bytes and descriptors may remain from the rejected frame.
func ReceiveFrame(conn *net.UnixConn, lim Limits) (Frame, []*os.File, error) {
	r := &rightsReader{
		conn:  conn,
		limit: lim.MaxFDs,
		oob:   make([]byte, syscall.CmsgSpace(4*min(max(lim.MaxFDs, 1), maxSendFDs))),
	}
	f, err := ReadFrame(r, lim.MaxFrameBytes)
	if err == nil {
		// ReadFull drops an error returned with the last bytes it needed.
		err = r.err
	}
	if err != nil {
		closeFiles(r.files)
		return Frame{}, nil, err
	}
	return f, r.files, nil
}

// rightsReader reads a stream socket and collects the SCM_RIGHTS descriptors
// that arrive along the way. A sender attaches descriptors to a frame's first
// byte, so they arrive on the first read; any later ones, or any past the
// limit, come from a peer trying to pile descriptors up and are closed at
// once.
type rightsReader struct {
	conn  *net.UnixConn
	oob   []byte
	limit int
	reads int
	files []*os.File
	err   error
}

func (r *rightsReader) Read(p []byte) (int, error) {
	if r.err != nil {
		// Reject at once rather than wait for body bytes a hostile peer may
		// never send.
		return 0, r.err
	}
	n, oobn, flags, _, err := r.conn.ReadMsgUnix(p, r.oob)
	r.reads++
	if oobn > 0 {
		r.collect(r.oob[:oobn])
	}
	if flags&syscall.MSG_CTRUNC != 0 {
		r.fail(errors.New("workerproc: descriptors truncated in transit"))
	}
	if r.err != nil {
		return n, r.err
	}
	if errors.Is(err, io.EOF) {
		// net wraps EOF in an OpError; io.ReadFull only recognises it bare,
		// and needs it to tell a clean end from a truncated frame.
		err = io.EOF
	}
	return n, err
}

func (r *rightsReader) collect(oob []byte) {
	// Parse one message at a time so a malformed later message cannot hide
	// descriptors recvmsg already installed and that still need closing.
	for len(oob) >= unix.CmsgLen(0) {
		hdr, data, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			r.fail(fmt.Errorf("workerproc: parse control message: %w", err))
			return
		}
		oob = rest
		if hdr.Level != unix.SOL_SOCKET || hdr.Type != unix.SCM_RIGHTS {
			continue
		}
		fds, err := unix.ParseUnixRights(&unix.SocketControlMessage{Header: hdr, Data: data})
		if err != nil {
			r.fail(fmt.Errorf("workerproc: parse descriptors: %w", err))
			continue
		}
		for _, fd := range fds {
			switch {
			case r.reads > 1:
				r.fail(errors.New("workerproc: descriptors arrived after the start of a frame"))
			case len(r.files) >= r.limit:
				r.fail(fmt.Errorf("workerproc: frame carries more than %d descriptors", r.limit))
			default:
				r.files = append(r.files, os.NewFile(uintptr(fd), "received"))
				continue
			}
			_ = unix.Close(fd)
		}
	}
}

func (r *rightsReader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

func marshalBody(f Frame, maxBytes int) ([]byte, error) {
	body, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("workerproc: marshal frame: %w", err)
	}
	if len(body) > maxBytes {
		return nil, fmt.Errorf("workerproc: frame body %d bytes exceeds cap %d", len(body), maxBytes)
	}
	return body, nil
}

func withHeader(body []byte) []byte {
	buf := make([]byte, 4+len(body))
	// #nosec G115 -- every caller has bounded len(body) by a frame cap far below 4 GiB.
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	return buf
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) != 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func closeFiles(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}
