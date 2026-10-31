//go:build linux

package yaraworker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// TestMain turns the test binary into a worker when a helper variable is
// set, so tests launch real worker processes without a separate binary.
// CSM_YARA_HELPER serves the workerproc protocol with fakeEngine.
func TestMain(m *testing.M) {
	if mode := os.Getenv("CSM_YARA_HELPER"); mode != "" {
		os.Exit(runYaraHelper(mode))
	}
	os.Exit(m.Run())
}

// runYaraHelper serves fakeEngine. Modes other than "worker" inject one
// fault in front of the real handler:
//
//	crash-on:<word>  exit when a scan's content contains <word>
//	load-error       answer load with an Error frame
//	report-ro        fail a scan whose descriptor is writable
//	report-sealed    fail a scan whose descriptor is not sealed
//	load-hang        never answer load
//	compile-nofd     answer compile with success but no descriptor
//	compile-huge     answer compile with a descriptor over MaxSerializedRules
//	compile-empty    answer compile with an empty descriptor
//	compile-hang     never finish compiling
//	compile-crash    exit on compile
func runYaraHelper(mode string) int {
	conn, err := workerproc.ChildConn()
	if err == nil {
		w := &worker{eng: fakeEngine{}}
		err = workerproc.Serve(context.Background(), conn,
			workerproc.Limits{MaxFrameBytes: yaraipc.MaxFrameBytes, MaxFDs: 1},
			func(ctx context.Context, req workerproc.Frame, fds []*os.File) (workerproc.Frame, []*os.File) {
				if f, out, ok := injectFault(mode, req, fds); ok {
					return f, out
				}
				return w.handle(ctx, req, fds)
			})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "yara helper:", mode, err)
		return 1
	}
	return 0
}

func injectFault(mode string, req workerproc.Frame, fds []*os.File) (workerproc.Frame, []*os.File, bool) {
	switch req.Op {
	case yaraipc.OpScanFD:
		if word, ok := strings.CutPrefix(mode, "crash-on:"); ok && len(fds) == 1 {
			data, _ := io.ReadAll(io.NewSectionReader(fds[0], 0, 1<<20))
			if bytes.Contains(data, []byte(word)) {
				os.Exit(3)
			}
		}
		if mode == "report-sealed" && len(fds) == 1 {
			want := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK
			if seals, err := unix.FcntlInt(fds[0].Fd(), unix.F_GET_SEALS, 0); err != nil || seals&want != want {
				return workerproc.Frame{Error: "scan descriptor is not sealed"}, nil, true
			}
		}
		if mode == "report-ro" && len(fds) == 1 {
			if fl, err := unix.FcntlInt(fds[0].Fd(), unix.F_GETFL, 0); err != nil || fl&unix.O_ACCMODE != unix.O_RDONLY {
				return workerproc.Frame{Error: "scan descriptor is writable"}, nil, true
			}
		}
	case yaraipc.OpLoad:
		if mode == "load-hang" {
			select {}
		}
		if mode == "load-error" {
			return workerproc.Frame{Error: "injected load failure"}, nil, true
		}
		if mode == "load-missing-count" {
			return workerproc.Frame{Payload: []byte(`{}`)}, nil, true
		}
	case yaraipc.OpPing:
		if payload, ok := map[string]string{
			"ping-negative":      `{"rule_count":-1}`,
			"ping-missing-count": `{}`,
			"ping-null-count":    `{"rule_count":null}`,
			"ping-null":          `null`,
		}[mode]; ok {
			return workerproc.Frame{Payload: []byte(payload)}, nil, true
		}
	case yaraipc.OpCompile:
		if payload, ok := map[string]string{
			"compile-negative":      `{"rule_count":-1}`,
			"compile-missing-count": `{}`,
			"compile-null-count":    `{"rule_count":null}`,
			"compile-null":          `null`,
			"compile-error-count":   `{"rule_count":1,"compile_error":"broken source"}`,
		}[mode]; ok {
			if mode == "compile-error-count" {
				return workerproc.Frame{Payload: []byte(payload)}, nil, true
			}
			out, err := yaraipc.SealedMemfd("csm-yara-reply", []byte(fakeRulesHeader+"evil\n"))
			if err != nil {
				return workerproc.Frame{Error: err.Error()}, nil, true
			}
			return workerproc.Frame{Payload: []byte(payload)}, []*os.File{out}, true
		}
		var out *os.File
		switch mode {
		case "compile-crash":
			os.Exit(3)
		case "compile-hang":
			time.Sleep(time.Hour)
			return workerproc.Frame{}, nil, true
		case "compile-nofd":
			return reply(yaraipc.CompileResult{RuleCount: 1}), nil, true
		case "compile-huge":
			fd, err := unix.MemfdCreate("csm-yara-huge", unix.MFD_CLOEXEC)
			if err != nil {
				return workerproc.Frame{Error: err.Error()}, nil, true
			}
			out = os.NewFile(uintptr(fd), "csm-yara-huge")
			// Sparse: the size is a claim, no memory backs it.
			if err := out.Truncate(yaraipc.MaxSerializedRules + 1); err != nil {
				_ = out.Close()
				return workerproc.Frame{Error: err.Error()}, nil, true
			}
		case "compile-empty":
			var err error
			if out, err = yaraipc.SealedMemfd("csm-yara-empty", nil); err != nil {
				return workerproc.Frame{Error: err.Error()}, nil, true
			}
		default:
			return workerproc.Frame{}, nil, false
		}
		return reply(yaraipc.CompileResult{RuleCount: 1}), []*os.File{out}, true
	}
	return workerproc.Frame{}, nil, false
}

// fakeEngine stands in for YARA-X in builds without it. A source line
// "marker:<word>" becomes a rule named <word> that matches data containing
// <word>; a source containing "syntax error" fails to compile. Compiled rules
// serialize as "FAKE1\n" followed by the words, one per line.
type fakeEngine struct{}

type fakeRules struct{ words []string }

const fakeRulesHeader = "FAKE1\n"

func (fakeEngine) Compile(sources []yara.Source) (Rules, error) {
	var words []string
	for _, src := range sources {
		if bytes.Contains(src.Text, []byte("syntax error")) {
			return nil, fmt.Errorf("compiling %s: syntax error", src.Name)
		}
		for _, line := range strings.Split(string(src.Text), "\n") {
			if w, ok := strings.CutPrefix(strings.TrimSpace(line), "marker:"); ok && w != "" {
				words = append(words, w)
			}
		}
	}
	return &fakeRules{words: words}, nil
}

func (fakeEngine) Load(r io.Reader) (Rules, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	rest, ok := bytes.CutPrefix(data, []byte(fakeRulesHeader))
	if !ok {
		return nil, errors.New("fake engine: not compiled rules")
	}
	var words []string
	for _, w := range strings.Split(string(rest), "\n") {
		if w != "" {
			words = append(words, w)
		}
	}
	return &fakeRules{words: words}, nil
}

func (r *fakeRules) Count() int { return len(r.words) }

func (r *fakeRules) Destroy() {}

func (r *fakeRules) WriteTo(w io.Writer) (int64, error) {
	n, err := io.WriteString(w, fakeRulesHeader+strings.Join(r.words, "\n"))
	return int64(n), err
}

func (r *fakeRules) Scan(data []byte) ([]yara.Match, error) {
	var out []yara.Match
	for _, w := range r.words {
		if bytes.Contains(data, []byte(w)) {
			out = append(out, yara.Match{RuleName: w, Meta: map[string]string{"severity": "critical"}})
		}
	}
	return out, nil
}
