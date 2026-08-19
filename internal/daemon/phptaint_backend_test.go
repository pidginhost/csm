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

	d.stopPHPTaintAnalyzer()
	if d.phpTaintSup != nil {
		t.Fatal("PHP taint supervisor survived shutdown")
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
