package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// OpHello is the first request on every worker connection. A worker built
// from a different version speaks a different protocol and must not get
// real requests.
const OpHello = "hello"

// Hello is the payload of a hello request and of its reply.
type Hello struct {
	Protocol int `json:"protocol"`
}

// HelloReply is a worker's answer to OpHello.
func HelloReply(protocol int) Frame {
	payload, _ := json.Marshal(Hello{Protocol: protocol}) // An int field cannot fail to marshal.
	return Frame{Payload: payload}
}

// Handshake sends hello and checks the worker answers with protocol. The
// reply is read under ctx's deadline, which is cleared afterwards. A reply
// with an op, an Error or any descriptor is refused.
func Handshake(ctx context.Context, conn *net.UnixConn, lim Limits, protocol int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("workerproc: hello: %w", err)
		}
		defer func() { _ = conn.SetDeadline(time.Time{}) }()
	}
	payload, err := json.Marshal(Hello{Protocol: protocol})
	if err != nil {
		return fmt.Errorf("workerproc: hello: %w", err)
	}
	if sendErr := SendFrame(conn, Frame{Op: OpHello, Payload: payload}, nil, lim.MaxFrameBytes); sendErr != nil {
		return fmt.Errorf("workerproc: hello: %w", sendErr)
	}
	// MaxFDs 0: ReceiveFrame closes and refuses any descriptor.
	reply, _, err := ReceiveFrame(conn, Limits{MaxFrameBytes: lim.MaxFrameBytes})
	if err != nil {
		return fmt.Errorf("workerproc: hello reply: %w", err)
	}
	switch {
	case reply.Error != "":
		return fmt.Errorf("workerproc: hello refused: %s", reply.Error)
	case reply.Op != "":
		return errors.New("workerproc: hello reply carries an op")
	}
	var h Hello
	if err := json.Unmarshal(reply.Payload, &h); err != nil {
		return fmt.Errorf("workerproc: hello reply: %w", err)
	}
	if h.Protocol != protocol {
		return fmt.Errorf("workerproc: worker speaks protocol %d, want %d", h.Protocol, protocol)
	}
	return nil
}
