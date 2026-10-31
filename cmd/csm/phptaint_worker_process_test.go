package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/phptaintipc"
	"github.com/pidginhost/csm/internal/phptaintworker"
	"github.com/pidginhost/csm/internal/workerproc"
)

func TestPHPTaintWorkerProcess(t *testing.T) {
	if os.Getenv("CSM_TEST_PHPTAINT_WORKER") != "1" {
		return
	}
	os.Args = []string{"csm", "phptaint-worker", "--memory-limit=536870912"}
	main()
	os.Exit(0) // The test runner's PASS line must not enter the protocol socket.
}

// Exercise CLI startup as well as the parser: stdout is the protocol socket,
// so any diagnostic there would corrupt the hello or a later response.
func TestSupervisedPHPTaintWorkerKeepsSocketFraming(t *testing.T) {
	exec := workerproc.ExecLauncher(os.Args[0], []string{"-test.run=^TestPHPTaintWorkerProcess$"},
		append(os.Environ(), "CSM_TEST_PHPTAINT_WORKER=1"))
	launch := func(ctx context.Context) (workerproc.Process, error) {
		p, err := exec(ctx)
		if err != nil {
			return nil, err
		}
		hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := workerproc.Handshake(hctx, p.Conn(), workerproc.Limits{MaxFrameBytes: phptaintipc.MaxFrameBytes}, phptaintipc.ProtocolVersion); err != nil {
			_ = p.Conn().Close()
			_ = p.Kill()
			<-p.Done()
			return nil, err
		}
		return p, nil
	}
	s, err := phptaintworker.NewSupervisor(phptaintworker.SupervisorConfig{
		Launch:  launch,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })

	const source = "<?php eval(curl_exec($c));"
	rep := s.Analyze(context.Background(), []byte(source+" }"))
	if rep.Status != phptaint.StatusPanic || rep.Reason != "panic: recovered panic during analysis" || len(rep.Results) != 0 {
		t.Fatalf("parser panic corrupted its response: %+v", rep)
	}
	for range 2 {
		rep := s.Analyze(context.Background(), []byte(source))
		if rep.Status != phptaint.StatusAnalyzed || rep.TotalResults != 1 || len(rep.Results) != 1 {
			t.Fatalf("worker response after parser panic: %+v", rep)
		}
		if got := rep.Results[0]; got.Source != "curl_exec" || got.Sink != "eval" {
			t.Fatalf("worker changed flow evidence: %+v", got)
		}
	}
	if s.SpawnCount() != 1 {
		t.Fatalf("parser panic replaced the worker: spawns=%d", s.SpawnCount())
	}
	if q := s.QueueStatuses(time.Now())["requests"]; q.DroppedTotal != 1 || q.InFlight != 0 || q.Depth != 0 {
		t.Fatalf("worker queue lost parser panic accounting: %+v", q)
	}
}
