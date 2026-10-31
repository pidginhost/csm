package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// Run the real worker entry point in a child test process.
func TestYaraWorkerProcess(t *testing.T) {
	if os.Getenv("CSM_TEST_YARA_WORKER") != "1" {
		return
	}
	os.Args = []string{"csm", "yara-worker", "--memory-limit=553648128"}
	main()
	os.Exit(0) // The test runner's PASS line must not enter the protocol socket.
}

// Exercise CLI startup: stdout is the protocol socket, so any diagnostic
// there would corrupt the hello or a later reply.
func TestSupervisedYaraWorkerKeepsSocketFraming(t *testing.T) {
	launch := workerproc.ExecLauncher(os.Args[0], []string{"-test.run=^TestYaraWorkerProcess$"},
		append(os.Environ(), "CSM_TEST_YARA_WORKER=1"))
	p, err := launch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = p.Conn().Close()
		_ = p.Kill()
		<-p.Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lim := workerproc.Limits{MaxFrameBytes: yaraipc.MaxFrameBytes}
	if err = workerproc.Handshake(ctx, p.Conn(), lim, yaraipc.ProtocolVersion); err != nil {
		t.Fatal(err)
	}
	if err = p.Conn().SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = workerproc.SendFrame(p.Conn(), workerproc.Frame{Op: yaraipc.OpPing}, nil, yaraipc.MaxFrameBytes); err != nil {
		t.Fatal(err)
	}
	reply, _, err := workerproc.ReceiveFrame(p.Conn(), lim)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply.Error, "no rules loaded") {
		t.Fatalf("ping before load = %+v, want the worker's own refusal", reply)
	}
}

// Started by hand, the worker has a terminal or a pipe on fd 0 and must
// refuse to run rather than read garbage frames.
func TestYaraWorkerRefusesNonSocketStdin(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestYaraWorkerProcess$") // #nosec G204 -- the test binary itself.
	cmd.Env = append(os.Environ(), "CSM_TEST_YARA_WORKER=1")
	cmd.Stdin = strings.NewReader("")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("worker ran without a socket on fd 0")
	}
	if !strings.Contains(stderr.String(), "not a socket") {
		t.Fatalf("stderr = %q, want the reason", stderr.String())
	}
}
