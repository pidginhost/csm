//go:build linux && yara

package yaraworker

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

func TestWorkerCompileRefusesFilesystemIncludes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outside.yar")
	if err := os.WriteFile(path, []byte(`rule outside { condition: true }`), 0600); err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf("include %q", path)
	legacy, err := yara.CompileSources([]yara.Source{{Name: "legacy.yar", Text: []byte(source)}})
	if err != nil {
		t.Fatalf("legacy include support changed: %v", err)
	}
	defer legacy.Destroy()
	if legacy.Count() != 1 {
		t.Fatalf("legacy include compiled %d rules, want 1", legacy.Count())
	}
	w := &worker{eng: DefaultEngine()}
	t.Cleanup(w.close)
	args, all := compileArgs(map[string]string{"request.yar": source}, "request.yar")
	req, err := yaraipc.EncodePayload(yaraipc.OpCompile, args)
	if err != nil {
		t.Fatal(err)
	}
	resp, fds := w.compile(workerproc.Frame{Payload: req.Payload}, memfd(t, all))
	for _, fd := range fds {
		defer fd.Close()
	}
	var result yaraipc.CompileResult
	decode(t, resp, &result)
	if result.CompileError == "" || !strings.Contains(result.CompileError, "include statements not allowed") || len(fds) != 0 {
		t.Fatalf("filesystem include was not refused before opening: %+v, %d fds", result, len(fds))
	}
}

func TestWorkerRealEngineRoundTrip(t *testing.T) {
	w := &worker{eng: DefaultEngine()}
	t.Cleanup(w.close)
	args, all := compileArgs(map[string]string{"test.yar": `rule hit { meta: severity = "critical" strings: $a = "marker" condition: $a }`}, "test.yar")
	req, err := yaraipc.EncodePayload(yaraipc.OpCompile, args)
	if err != nil {
		t.Fatal(err)
	}
	resp, fds := w.compile(workerproc.Frame{Payload: req.Payload}, memfd(t, all))
	var result yaraipc.CompileResult
	decode(t, resp, &result)
	if result.RuleCount != 1 || result.CompileError != "" || len(fds) != 1 {
		t.Fatalf("compile = %+v, %d fds", result, len(fds))
	}
	defer fds[0].Close()
	resp, _ = w.load(fds[0])
	if resp.Error != "" {
		t.Fatal(resp.Error)
	}
	for _, data := range []string{"marker", "clean"} {
		f := memfd(t, data)
		if _, err := f.Seek(2, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		req, err := yaraipc.EncodePayload(yaraipc.OpScanFD, yaraipc.ScanFDArgs{MaxBytes: len(data)})
		if err != nil {
			t.Fatal(err)
		}
		resp, _ = w.scan(workerproc.Frame{Payload: req.Payload}, f)
		matches, err := yaraipc.DecodeScanReply(resp.Payload)
		if resp.Error != "" || err != nil {
			t.Fatalf("scan = %+v, %v", resp, err)
		}
		if data == "marker" {
			if len(matches) != 1 || matches[0].RuleName != "hit" || matches[0].Meta["severity"] != "critical" {
				t.Fatalf("matches = %+v", matches)
			}
		} else if matches == nil || len(matches) != 0 {
			t.Fatalf("clean scan = %+v", matches)
		}
		if off, err := f.Seek(0, io.SeekCurrent); err != nil || off != 2 {
			t.Fatalf("descriptor offset = %d, %v", off, err)
		}
	}
}

func TestWorkerRealCompileErrorFitsFrame(t *testing.T) {
	w := &worker{eng: DefaultEngine()}
	source := "rule bad { condition: " + strings.Repeat("x", yaraipc.MaxFrameBytes) + " }"
	args, all := compileArgs(map[string]string{"bad.yar": source}, "bad.yar")
	req, err := yaraipc.EncodePayload(yaraipc.OpCompile, args)
	if err != nil {
		t.Fatal(err)
	}
	resp, fds := w.compile(workerproc.Frame{Payload: req.Payload}, memfd(t, all))
	for _, fd := range fds {
		defer fd.Close()
	}
	var result yaraipc.CompileResult
	decode(t, resp, &result)
	if result.CompileError == "" || len(fds) != 0 {
		t.Fatal("bad source did not return a compile error")
	}
	if err := workerproc.WriteFrame(io.Discard, resp, yaraipc.MaxFrameBytes); err != nil {
		t.Fatalf("compile error cannot be sent as a result: %v", err)
	}
}
