package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/phptaint"
	"github.com/pidginhost/csm/internal/phptaintworker"
)

func TestPHPTaintWorkerProcess(t *testing.T) {
	if os.Getenv("CSM_TEST_PHPTAINT_WORKER") != "1" {
		return
	}
	os.Args = []string{"csm", "phptaint-worker"}
	main()
	os.Exit(0) // The test runner's PASS line must not enter the protocol socket.
}

// Exercise CLI startup as well as the parser: stdout is the protocol socket,
// so any diagnostic there would corrupt this or the next response.
func TestSupervisedPHPTaintWorkerKeepsSocketFraming(t *testing.T) {
	s, err := phptaintworker.NewSupervisor(phptaintworker.SupervisorConfig{
		Command: os.Args[0],
		Args:    []string{"-test.run=^TestPHPTaintWorkerProcess$"},
		Env:     append(os.Environ(), "CSM_TEST_PHPTAINT_WORKER=1"),
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
