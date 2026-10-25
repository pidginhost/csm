package workerproc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// unitHelperArg marks this test binary running as a unit worker: either as
// the fake systemd-run (the argument follows the systemd-run flags) or as the
// command of a real transient unit.
const unitHelperArg = "csm-unit-helper"

func TestMain(m *testing.M) {
	for i, arg := range os.Args {
		if arg == unitHelperArg {
			os.Exit(runUnitHelper(os.Args[i+1:]))
		}
	}
	os.Exit(m.Run())
}

// unitHelperOps answers test requests inside a unit helper. The kernel tests
// add their own.
var unitHelperOps = map[string]func(json.RawMessage) Frame{
	"sleep": func(payload json.RawMessage) Frame {
		var ms int
		if err := json.Unmarshal(payload, &ms); err != nil {
			return Frame{Error: err.Error()}
		}
		time.Sleep(time.Duration(ms) * time.Millisecond)
		out, _ := json.Marshal(map[string]int{"pid": os.Getpid()})
		return Frame{Payload: out}
	},
}

// runUnitHelper serves fd 0. Its first argument is the protocol to answer
// hello with, or exit-now to fail before any hello.
func runUnitHelper(args []string) int {
	if len(args) == 0 {
		return 2
	}
	if args[0] == "exit-now" {
		return 1
	}
	if args[0] == "stderr-then-exit" {
		fmt.Fprint(os.Stderr, "hello from stderr\n\x1b[31mforged\n")
		return 1
	}
	protocol, err := strconv.Atoi(args[0])
	if err != nil {
		return 2
	}
	signal.Ignore(syscall.SIGXFSZ)
	conn, err := ChildConn()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	err = Serve(context.Background(), conn, Limits{MaxFrameBytes: 1 << 20, MaxFDs: 1}, func(_ context.Context, req Frame, _ []*os.File) (Frame, []*os.File) {
		if req.Op == OpHello {
			return HelloReply(protocol), nil
		}
		op, ok := unitHelperOps[req.Op]
		if !ok {
			return Frame{Error: "unknown op " + req.Op}, nil
		}
		return op(req.Payload), nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
