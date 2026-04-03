package modsec

import (
	"testing"
)

func TestReloadSuccess(t *testing.T) {
	output, err := Reload("echo reload-ok")
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if output != "reload-ok\n" {
		t.Errorf("output = %q, want %q", output, "reload-ok\n")
	}
}

func TestReloadFailure(t *testing.T) {
	_, err := Reload("false") // exits with code 1
	if err == nil {
		t.Error("expected error for failing command")
	}
}

func TestReloadEmptyCommand(t *testing.T) {
	_, err := Reload("")
	if err == nil {
		t.Error("expected error for empty command")
	}
}
