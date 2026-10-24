package workerproc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestCallClassifiesInvalidWireReplies(t *testing.T) {
	for _, tc := range []struct {
		name       string
		wire       []byte
		fdCount    int
		fdLimit    int
		lateFDs    bool
		wantReason string
		wantText   string
		wantCause  error
	}{
		{
			name: "oversize header", wire: []byte{0, 16, 0, 1},
			wantReason: ReasonProtocol,
			wantText:   "workerproc: declared frame size 1048577 exceeds cap 1048576",
		},
		{
			name: "invalid JSON", wire: withHeader([]byte("{")),
			wantReason: ReasonProtocol,
			wantText:   "workerproc: unmarshal frame: unexpected end of JSON input",
		},
		{
			name: "wrong JSON type", wire: withHeader([]byte("[]")),
			wantReason: ReasonProtocol,
			wantText:   "workerproc: unmarshal frame: json: cannot unmarshal array into Go value of type workerproc.Frame",
		},
		{
			name: "empty frame", wire: withHeader(nil),
			wantReason: ReasonProtocol,
			wantText:   "workerproc: unmarshal frame: unexpected end of JSON input",
		},
		{
			name: "excess descriptors", wire: withHeader([]byte("{}")), fdCount: 2, fdLimit: 1,
			wantReason: ReasonProtocol,
			wantText:   "workerproc: read body: workerproc: frame carries more than 1 descriptors",
		},
		{
			name: "truncated descriptors", wire: withHeader([]byte("{}")), fdCount: 3, fdLimit: 2,
			wantReason: ReasonProtocol,
			wantText:   "workerproc: read body: workerproc: descriptors truncated in transit",
		},
		{
			name: "late descriptors", wire: withHeader([]byte("{}")), fdCount: 1, fdLimit: 1, lateFDs: true,
			wantReason: ReasonProtocol,
			wantText:   "workerproc: descriptors arrived after the start of a frame",
		},
		{
			name:       "closed socket",
			wantReason: ReasonCrash, wantCause: io.EOF,
			wantText: "workerproc: read header: EOF",
		},
		{
			name: "partial header", wire: []byte{0, 0},
			wantReason: ReasonCrash, wantCause: io.ErrUnexpectedEOF,
			wantText: "workerproc: read header: unexpected EOF",
		},
		{
			name: "partial body", wire: []byte{0, 0, 0, 2, '{'},
			wantReason: ReasonCrash, wantCause: io.ErrUnexpectedEOF,
			wantText: "workerproc: read body: unexpected EOF",
		},
	} {
		for _, oom := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/oom=%t", tc.name, oom), func(t *testing.T) {
				var log failureLog
				s := reasonSupervisor(t, helperLauncher(t, "echo"), 5*time.Second, &log)
				s.cfg.Limits.MaxFDs = tc.fdLimit
				parent, peer := socketPair(t)
				proc := liveProcess()
				if oom {
					proc = oomProcess{proc}
				}
				s.child = &child{proc: proc, conn: unixTransport{conn: parent, lim: s.cfg.Limits}}
				wire := tc.wire
				if tc.lateFDs {
					if err := writeFull(peer, wire[:4]); err != nil {
						t.Fatal(err)
					}
					wire = wire[4:]
				}
				if tc.fdCount > 0 {
					r, w, err := os.Pipe()
					if err != nil {
						t.Fatal(err)
					}
					defer r.Close()
					defer w.Close()
					fds := make([]int, tc.fdCount)
					for i := range fds {
						fds[i] = int(w.Fd())
					}
					if _, _, err := peer.WriteMsgUnix(wire, syscall.UnixRights(fds...), nil); err != nil {
						t.Fatal(err)
					}
				} else if err := writeFull(peer, wire); err != nil {
					t.Fatal(err)
				}
				if err := peer.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				before := openFDs(t)
				_, fds, err := s.Call(context.Background(), Frame{Op: "work"}, nil, okCheck)
				defer closeFiles(fds)
				want := tc.wantReason
				if oom && want == ReasonCrash {
					want = ReasonOOM
				}
				if FailureReason(err) != want || !errors.Is(err, ErrWorkerFailed) || fds != nil {
					t.Errorf("Call = %v, reason %q, descriptors %d; want %q worker failure", err, FailureReason(err), len(fds), want)
				}
				if err == nil || err.Error() != "test worker: read reply: "+tc.wantText {
					t.Errorf("error text changed: %v", err)
				}
				if tc.wantCause != nil && !errors.Is(err, tc.wantCause) {
					t.Errorf("lost underlying error %v: %v", tc.wantCause, err)
				}
				if got := FailureReason(fmt.Errorf("caller: %w", err)); got != want {
					t.Errorf("wrapped failure reason = %q, want %q", got, want)
				}
				if got := log.got(); len(got) != 1 || got[0] != want {
					t.Errorf("hook saw %q, want %q", got, want)
				}
				if st := s.Stats(); len(st.Kills) != 1 || st.Kills[want] != 1 || st.ConsecutiveFailures != 1 || st.Running {
					t.Errorf("failure accounting: %+v", st)
				}
				assertNoFDLeak(t, before-1) // The supervisor closed its socket.
			})
		}
	}
}
