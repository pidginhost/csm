package checks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// extractPHPString — pure string parser that pulls the FIRST quoted value.
// Callers (parseKeyString) strip the key prefix first, so these inputs
// mimic the "value half" of a `define('KEY', 'value')` line.

func TestExtractPHPStringSingleQuoted(t *testing.T) {
	if got := extractPHPString(" 'hello');"); got != "hello" {
		t.Errorf("single-quoted = %q, want %q", got, "hello")
	}
}

func TestExtractPHPStringDoubleQuoted(t *testing.T) {
	if got := extractPHPString(` "world");`); got != "world" {
		t.Errorf("double-quoted = %q, want %q", got, "world")
	}
}

func TestExtractPHPStringFirstQuoteTypeWins(t *testing.T) {
	// Single quote appears first — returns single-quoted content even
	// when a double-quoted string follows.
	if got := extractPHPString(`'first' "second"`); got != "first" {
		t.Errorf("first-quote type wins = %q, want %q", got, "first")
	}
}

func TestExtractPHPStringFallsBackToDoubleWhenSingleClosureMissing(t *testing.T) {
	// Opening single quote but no closing single quote → function
	// continues to the double-quote iteration.
	if got := extractPHPString(`'unclosed "fallback";`); got != "fallback" {
		t.Errorf("unclosed-single + double = %q, want %q", got, "fallback")
	}
}

func TestExtractPHPStringNoQuotesReturnsEmpty(t *testing.T) {
	if got := extractPHPString("no quotes here"); got != "" {
		t.Errorf("plain string = %q, want empty", got)
	}
}

func TestExtractPHPStringEmptyInputReturnsEmpty(t *testing.T) {
	if got := extractPHPString(""); got != "" {
		t.Errorf("empty input = %q, want empty", got)
	}
}

// fileContentHash — osFS.ReadFile + sha256.

func TestFileContentHashSuccess(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "file.txt")
	if err := os.WriteFile(path, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := fileContentHash(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Known sha256("hello world")
	want := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if got != want {
		t.Errorf("hash = %q, want %q", got, want)
	}
}

func TestFileContentHashMissingFileReturnsError(t *testing.T) {
	withMockOS(t, &mockOS{
		readFile: func(string) ([]byte, error) { return nil, errors.New("nope") },
	})
	_, err := fileContentHash("/whatever")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// fixKillAndQuarantine dispatcher branches (no actual kills).

func TestFixKillAndQuarantineEmptyPath(t *testing.T) {
	res := fixKillAndQuarantine("", "PID: 123")
	if res.Success || !strings.Contains(res.Error, "could not extract") {
		t.Errorf("empty path should error, got %+v", res)
	}
}

func TestFixKillAndQuarantineNoPIDProceedsToQuarantine(t *testing.T) {
	// No "PID:" in details → extractPID returns empty → skip kill, go
	// straight to fixQuarantine. With an invalid path fixQuarantine
	// will still error (path not under allowed roots), surfacing the
	// path-validation error rather than panicking.
	res := fixKillAndQuarantine("/etc/passwd", "no pid info here")
	if res.Success {
		t.Errorf("expected path-validation failure, got Success")
	}
}

func TestFixKillAndQuarantineLowPIDSkipsKill(t *testing.T) {
	// pidInt must be > 1 to attempt kill. PID=0 or PID=1 skip the Kill
	// call but still proceed to fixQuarantine. With an outside-root path
	// fixQuarantine errors, but we must not have crashed.
	res := fixKillAndQuarantine("/etc/passwd", "PID: 1")
	if res.Success {
		t.Errorf("expected error, got Success")
	}
}
