//go:build linux && yara

package yaraworker

import (
	"context"
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/workerproc"
)

func TestBackendRealEngineRecovery(t *testing.T) {
	if os.Getenv("CSM_YARA_REAL_ENGINE_HELPER") == "1" {
		conn, err := workerproc.ChildConn()
		if err == nil {
			err = Serve(context.Background(), conn, DefaultEngine())
		}
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	launch := workerproc.ExecLauncher(os.Args[0], []string{"-test.run=^TestBackendRealEngineRecovery$"},
		append(os.Environ(), "CSM_YARA_REAL_ENGINE_HELPER=1"))
	fx := &backendFixture{
		dir:       rulesDir(t, map[string]string{"rules.yar": "rule broken { condition: }"}),
		disabled:  []string{"disabled"},
		compileFn: launch,
		scanFn:    launch,
	}
	b := newBackend(t, fx)
	if err := b.Reload(); err == nil || b.CompileError() == "" {
		t.Fatal("invalid rules did not report a compile failure")
	}
	if _, err := b.ScanBytesChecked([]byte("marker")); err == nil {
		t.Fatal("uncompiled rules allowed a clean scan")
	}
	writeRule(t, fx.dir, "rules.yar", `
rule enabled { meta: severity = "critical" strings: $a = "marker" condition: $a }
rule disabled { condition: true }
`)
	if err := b.Reload(); err != nil {
		t.Fatal(err)
	}
	if b.CompileError() != "" || b.RuleCount() != 1 {
		t.Fatalf("recovered rules = %d, error = %q", b.RuleCount(), b.CompileError())
	}
	matches, err := b.ScanBytesChecked([]byte("marker"))
	if err != nil || len(matches) != 1 || matches[0].RuleName != "enabled" || matches[0].Meta["severity"] != "critical" {
		t.Fatalf("recovered scan = %+v, %v", matches, err)
	}
	if matches, err := b.ScanBytesChecked([]byte("clean")); err != nil || len(matches) != 0 {
		t.Fatalf("disabled rule matched after recovery: %+v, %v", matches, err)
	}
}
