package workerproc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
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
// exchange honors ctx's cancellation and deadline, clearing the connection
// deadline afterwards. A reply with an op, an Error or any descriptor is
// refused. The caller must close the connection after a failed handshake.
func Handshake(ctx context.Context, conn *net.UnixConn, lim Limits, protocol int) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("workerproc: hello: %w", err)
		}
	}
	var canceled sync.WaitGroup
	canceled.Add(1)
	stop := context.AfterFunc(ctx, func() {
		defer canceled.Done()
		_ = conn.SetDeadline(time.Now())
	})
	defer func() {
		// A cancellation callback already running must finish before the
		// deadline is cleared, or it could poison the next exchange.
		if !stop() {
			canceled.Wait()
		}
		_ = conn.SetDeadline(time.Time{})
		if ctxErr := ctx.Err(); ctxErr != nil {
			retErr = ctxErr
		}
	}()
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
