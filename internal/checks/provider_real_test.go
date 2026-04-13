package checks

import (
	"context"
	"os"
	"testing"
)

// Test the real implementations to cover the provider.go delegates.

func TestRealOSReadFile(t *testing.T) {
	f := t.TempDir() + "/test.txt"
	_ = os.WriteFile(f, []byte("hello"), 0644)

	r := realOS{}
	data, err := r.ReadFile(f)
	if err != nil || string(data) != "hello" {
		t.Errorf("ReadFile: %v, %q", err, data)
	}
}

func TestRealOSStat(t *testing.T) {
	r := realOS{}
	_, err := r.Stat(t.TempDir())
	if err != nil {
		t.Errorf("Stat: %v", err)
	}
}

func TestRealOSGlob(t *testing.T) {
	d := t.TempDir()
	_ = os.WriteFile(d+"/a.txt", nil, 0644)
	r := realOS{}
	matches, _ := r.Glob(d + "/*.txt")
	if len(matches) != 1 {
		t.Errorf("Glob: %v", matches)
	}
}

func TestRealCmdRunEcho(t *testing.T) {
	r := realCmd{}
	out, err := r.Run("echo", "hello")
	if err != nil {
		t.Fatalf("Run echo: %v", err)
	}
	if len(out) == 0 {
		t.Error("echo should produce output")
	}
}

func TestRealCmdRunAllowNonZero(t *testing.T) {
	r := realCmd{}
	out, err := r.RunAllowNonZero("echo", "test")
	if err != nil {
		t.Fatalf("RunAllowNonZero: %v", err)
	}
	_ = out
}

func TestRealCmdRunContext(t *testing.T) {
	r := realCmd{}
	out, err := r.RunContext(context.Background(), "echo", "ctx")
	if err != nil {
		t.Fatalf("RunContext: %v", err)
	}
	_ = out
}

func TestRealCmdRunWithEnv(t *testing.T) {
	r := realCmd{}
	out, err := r.RunWithEnv("echo", []string{"envtest"}, "FOO=bar")
	if err != nil {
		t.Fatalf("RunWithEnv: %v", err)
	}
	_ = out
}

func TestRealCmdLookPath(t *testing.T) {
	r := realCmd{}
	path, err := r.LookPath("echo")
	if err != nil {
		t.Fatalf("LookPath echo: %v", err)
	}
	if path == "" {
		t.Error("echo should be found")
	}
}
