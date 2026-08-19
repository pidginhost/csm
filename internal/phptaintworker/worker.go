// Package phptaintworker is the child side of PHP taint analysis.
//
// The analyzer's parser can enter an infinite loop on attacker-controlled
// input. Two such inputs are known, both found by accident rather than by
// audit, in a hand-written lexer that has been unmaintained since 2022. A loop
// is not a panic, so recover() cannot catch it, and the parser never checks
// context, so no deadline inside this process can stop it. Running the analysis
// here means the parent can stop it the only way that works: by killing this
// process.
//
// Consequences for anything written in this package: a request that never
// returns is an expected outcome, not a bug to defend against locally, and this
// side must stay simple enough that the parent's timeout is the sole liveness
// mechanism. Do not add an internal watchdog -- it would only ever fire on
// inputs the parent already handles, while giving a false impression that this
// process can rescue itself.
package phptaintworker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/phptaintipc"
)

// Serve reads request frames from r and writes response frames to w. It checks
// ctx between frames, not from inside the parser; the parent process remains
// the sole liveness boundary. It is the whole worker: one request at a time, no
// concurrency, no state carried between requests.
//
// A valid frame with a bad operation or payload is answered with an error and
// the loop continues. Dropping the process for that peer mistake would make the
// parent replace its worker repeatedly. Broken framing ends the loop because a
// trustworthy boundary for the next request no longer exists.
func Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := phptaintipc.ReadFrame(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		resp := handle(ctx, req)
		if err := phptaintipc.WriteFrame(w, resp); err != nil {
			return err
		}
	}
}

func handle(ctx context.Context, req phptaintipc.Frame) phptaintipc.Frame {
	switch req.Op {
	case phptaintipc.OpPing:
		return reply(phptaintipc.OpPing, phptaintipc.PingResult{OK: true})

	case phptaintipc.OpAnalyze:
		var args phptaintipc.AnalyzeArgs
		if err := phptaintipc.DecodePayload(req, &args); err != nil {
			return phptaintipc.Frame{Error: err.Error()}
		}
		// Analyze already contains its own panic boundary and reports one as a
		// coverage gap, so there is nothing to recover here.
		report := phptaint.Analyze(ctx, args.Source)
		return reply(phptaintipc.OpAnalyze, phptaintipc.AnalyzeResult{Report: report})

	default:
		return phptaintipc.Frame{Error: fmt.Sprintf("phptaintworker: unknown op %q", req.Op)}
	}
}

func reply(op string, v any) phptaintipc.Frame {
	frame, err := phptaintipc.EncodePayload(op, v)
	if err != nil {
		return phptaintipc.Frame{Error: err.Error()}
	}
	// A response carries no op: the parent matches replies by order on a
	// single-flight connection, and echoing the op would invite a reader to
	// match on it instead.
	frame.Op = ""
	return frame
}

// signalIgnore makes a signal a no-op for this process. The supervisor tests
// use it to build a child that a catchable signal cannot stop, which is what a
// parser loop behaves like.
func signalIgnore(sig os.Signal) {
	signal.Ignore(sig)
}
