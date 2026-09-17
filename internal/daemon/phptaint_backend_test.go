package daemon

import "testing"

func TestPHPTaintAnalyzerLifecycleInstallsLazySupervisor(t *testing.T) {
	d := &Daemon{binaryPath: "/opt/csm/csm"}
	if err := d.initPHPTaintAnalyzer(); err != nil {
		t.Fatal(err)
	}
	if d.phpTaintSup == nil {
		t.Fatal("PHP taint supervisor was not installed")
	}
	if got := d.phpTaintSup.SpawnCount(); got != 0 {
		t.Fatalf("worker spawned during initialization: %d", got)
	}
	q, ok := d.QueueStatuses()["php_taint.requests"]
	if !ok || q.Status != "ok" || !q.CapacityUnavailable || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("PHP worker queue was not published: found=%v status=%+v", ok, q)
	}

	d.stopPHPTaintAnalyzer()
	if d.phpTaintSup != nil {
		t.Fatal("PHP taint supervisor survived shutdown")
	}
	if q, ok := d.QueueStatuses()["php_taint.requests"]; !ok || q.Status != "ok" || q.Depth != 0 || q.InFlight != 0 || q.DroppedTotal != 0 {
		t.Fatalf("stopped worker health was discarded: found=%v status=%+v", ok, q)
	}
}

func TestPHPTaintAnalyzerRejectsMissingBinary(t *testing.T) {
	d := &Daemon{}
	if err := d.initPHPTaintAnalyzer(); err == nil {
		t.Fatal("empty worker command was accepted")
	}
	if d.phpTaintSup != nil {
		t.Fatal("failed initialization retained a supervisor")
	}
}
