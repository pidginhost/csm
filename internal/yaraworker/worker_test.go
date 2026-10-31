//go:build linux

package yaraworker

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// startWorker serves fakeEngine on one end of a socket pair and returns the
// other end.
func startWorker(t *testing.T) *net.UnixConn {
	t.Helper()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conns := make([]*net.UnixConn, 2)
	for i, fd := range pair {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c.(*net.UnixConn)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), conns[1], fakeEngine{}) }()
	t.Cleanup(func() {
		_ = conns[0].Close()
		<-done
		_ = conns[1].Close()
	})
	return conns[0]
}

func call(t *testing.T, c *net.UnixConn, op string, args any, fds ...*os.File) (workerproc.Frame, []*os.File) {
	t.Helper()
	var payload json.RawMessage
	if args != nil {
		var err error
		if payload, err = json.Marshal(args); err != nil {
			t.Fatal(err)
		}
	}
	if err := workerproc.SendFrame(c, workerproc.Frame{Op: op, Payload: payload}, fds, yaraipc.MaxFrameBytes); err != nil {
		t.Fatal(err)
	}
	reply, replyFDs, err := workerproc.ReceiveFrame(c, workerproc.Limits{MaxFrameBytes: yaraipc.MaxFrameBytes, MaxFDs: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, f := range replyFDs {
			_ = f.Close()
		}
	})
	return reply, replyFDs
}

func memfd(t *testing.T, data string) *os.File {
	t.Helper()
	f, err := yaraipc.SealedMemfd("csm-yara-test", []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func decode(t *testing.T, f workerproc.Frame, out any) {
	t.Helper()
	if f.Error != "" {
		t.Fatalf("reply error: %s", f.Error)
	}
	if err := json.Unmarshal(f.Payload, out); err != nil {
		t.Fatalf("decode %s: %v", f.Payload, err)
	}
}

func compileArgs(texts map[string]string, order ...string) (yaraipc.CompileArgs, string) {
	var args yaraipc.CompileArgs
	var all strings.Builder
	for _, name := range order {
		args.Sources = append(args.Sources, yaraipc.SourceSpan{Name: name, Size: int64(len(texts[name]))})
		all.WriteString(texts[name])
	}
	return args, all.String()
}

// loadedWorker returns a worker that has loaded rules for words.
func loadedWorker(t *testing.T, words ...string) *net.UnixConn {
	t.Helper()
	c := startWorker(t)
	rules := fakeRulesHeader + strings.Join(words, "\n")
	var res yaraipc.LoadResult
	reply, _ := call(t, c, yaraipc.OpLoad, nil, memfd(t, rules))
	decode(t, reply, &res)
	if res.RuleCount != len(words) {
		t.Fatalf("loaded %d rules, want %d", res.RuleCount, len(words))
	}
	return c
}

func TestWorkerCompileReturnsSealedRules(t *testing.T) {
	c := startWorker(t)
	args, all := compileArgs(map[string]string{"a.yar": "marker:evil\n", "b.yar": "marker:other\n"}, "a.yar", "b.yar")
	reply, fds := call(t, c, yaraipc.OpCompile, args, memfd(t, all))
	var res yaraipc.CompileResult
	decode(t, reply, &res)
	if res.RuleCount != 2 || res.CompileError != "" {
		t.Fatalf("result = %+v, want 2 rules", res)
	}
	if len(fds) != 1 {
		t.Fatalf("compile reply carried %d descriptors, want 1", len(fds))
	}
	data, err := io.ReadAll(io.NewSectionReader(fds[0], 0, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != fakeRulesHeader+"evil\nother" {
		t.Fatalf("serialized rules = %q", data)
	}
	seals, err := unix.FcntlInt(fds[0].Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK; seals&want != want {
		t.Fatalf("seals = %#x, want write, grow and shrink sealed", seals)
	}
}

func TestWorkerCompileErrorIsAResult(t *testing.T) {
	c := startWorker(t)
	args, all := compileArgs(map[string]string{"bad.yar": "syntax error"}, "bad.yar")
	reply, fds := call(t, c, yaraipc.OpCompile, args, memfd(t, all))
	var res yaraipc.CompileResult
	decode(t, reply, &res)
	if !strings.Contains(res.CompileError, "bad.yar") || res.RuleCount != 0 {
		t.Fatalf("result = %+v, want a compile error naming bad.yar", res)
	}
	if len(fds) != 0 {
		t.Fatalf("a failed compile returned %d descriptors", len(fds))
	}
}

func TestWorkerCompileRejectsBadSpans(t *testing.T) {
	many := make([]yaraipc.SourceSpan, yaraipc.MaxSources+1)
	for i := range many {
		many[i] = yaraipc.SourceSpan{Name: "r.yar"}
	}
	for _, tc := range []struct {
		name  string
		args  yaraipc.CompileArgs
		input string
	}{
		{"size mismatch", yaraipc.CompileArgs{Sources: []yaraipc.SourceSpan{{Name: "a.yar", Size: 3}}}, "marker:x\n"},
		{"too many", yaraipc.CompileArgs{Sources: many}, "x"},
		{"path name", yaraipc.CompileArgs{Sources: []yaraipc.SourceSpan{{Name: "../x", Size: 1}}}, "x"},
		{"empty name", yaraipc.CompileArgs{Sources: []yaraipc.SourceSpan{{Name: "", Size: 1}}}, "x"},
		{"long name", yaraipc.CompileArgs{Sources: []yaraipc.SourceSpan{{Name: strings.Repeat("n", 256), Size: 1}}}, "x"},
		{"negative size", yaraipc.CompileArgs{Sources: []yaraipc.SourceSpan{{Name: "a.yar", Size: -1}, {Name: "b.yar", Size: 2}}}, "x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := startWorker(t)
			reply, fds := call(t, c, yaraipc.OpCompile, tc.args, memfd(t, tc.input))
			if reply.Error == "" || len(fds) != 0 {
				t.Fatalf("bad spans were accepted: %+v, %d fds", reply, len(fds))
			}
		})
	}
}

func TestWorkerScanBeforeLoadFails(t *testing.T) {
	c := startWorker(t)
	if reply, _ := call(t, c, yaraipc.OpPing, nil); reply.Error == "" {
		t.Fatal("ping before load answered")
	}
	c = startWorker(t)
	if reply, _ := call(t, c, yaraipc.OpScanFD, yaraipc.ScanFDArgs{MaxBytes: 4}, memfd(t, "evil")); reply.Error == "" {
		t.Fatal("scan before load answered")
	}
}

func TestWorkerLoadThenScan(t *testing.T) {
	c := loadedWorker(t, "evil")
	reply, fds := call(t, c, yaraipc.OpScanFD, yaraipc.ScanFDArgs{MaxBytes: 10}, memfd(t, "xx evil xx"))
	if reply.Error != "" || len(fds) != 0 {
		t.Fatalf("scan reply = %+v, %d fds", reply, len(fds))
	}
	matches, err := yaraipc.DecodeScanReply(reply.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].RuleName != "evil" || matches[0].Meta["severity"] != "critical" {
		t.Fatalf("matches = %+v", matches)
	}
	var ping yaraipc.LoadResult
	reply, _ = call(t, c, yaraipc.OpPing, nil)
	decode(t, reply, &ping)
	if ping.RuleCount != 1 {
		t.Fatalf("ping rule count = %d, want 1", ping.RuleCount)
	}
}

func TestWorkerScanCleanHasEmptyMatchesArray(t *testing.T) {
	c := loadedWorker(t, "evil")
	reply, _ := call(t, c, yaraipc.OpScanFD, yaraipc.ScanFDArgs{MaxBytes: 5}, memfd(t, "clean"))
	if reply.Error != "" || !strings.Contains(string(reply.Payload), `"matches":[]`) {
		t.Fatalf("clean reply = %+v, want an explicit empty matches array", reply)
	}
}

func TestWorkerScanShortDescriptorFails(t *testing.T) {
	c := loadedWorker(t, "evil")
	if reply, _ := call(t, c, yaraipc.OpScanFD, yaraipc.ScanFDArgs{MaxBytes: 100}, memfd(t, "evil")); reply.Error == "" {
		t.Fatal("a descriptor shorter than MaxBytes scanned")
	}
}

func TestWorkerScanRejectsInvalidSize(t *testing.T) {
	for _, size := range []int{0, -1} {
		c := loadedWorker(t, "evil")
		if reply, _ := call(t, c, yaraipc.OpScanFD, yaraipc.ScanFDArgs{MaxBytes: size}, memfd(t, "evil")); reply.Error == "" {
			t.Fatalf("MaxBytes %d scanned", size)
		}
	}
}

func TestWorkerRefusesRemovedOps(t *testing.T) {
	for _, op := range []string{"scan_file", "scan_bytes", "reload"} {
		c := loadedWorker(t, "evil")
		if reply, _ := call(t, c, op, map[string]any{"path": "/etc/shadow"}); reply.Error == "" {
			t.Fatalf("op %s answered", op)
		}
	}
}

func TestWorkerScanNeedsOneDescriptor(t *testing.T) {
	c := loadedWorker(t, "evil")
	if reply, _ := call(t, c, yaraipc.OpScanFD, yaraipc.ScanFDArgs{MaxBytes: 4}); reply.Error == "" {
		t.Fatal("scan_fd without a descriptor answered")
	}
}

func TestWorkerRefusesDescriptorOnPing(t *testing.T) {
	c := loadedWorker(t, "evil")
	if reply, _ := call(t, c, yaraipc.OpPing, nil, memfd(t, "x")); reply.Error == "" {
		t.Fatal("ping carrying a descriptor answered")
	}
}
