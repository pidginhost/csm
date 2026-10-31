package yaraworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// Engine compiles rule text and loads compiled rules. DefaultEngine is
// YARA-X; tests substitute a fake because plain builds have no engine.
type Engine interface {
	Compile(sources []yara.Source) (Rules, error)
	Load(r io.Reader) (Rules, error)
}

// Rules is a compiled rule set as the worker uses it.
type Rules interface {
	Count() int
	WriteTo(w io.Writer) (int64, error)
	Scan(data []byte) ([]yara.Match, error)
}

// DefaultEngine is YARA-X. In a build without it every call returns
// yara.ErrNoEngine.
func DefaultEngine() Engine { return yaraEngine{} }

type yaraEngine struct{}

func (yaraEngine) Compile(sources []yara.Source) (Rules, error) {
	r, err := yara.CompileSources(sources)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (yaraEngine) Load(rd io.Reader) (Rules, error) {
	r, err := yara.LoadRules(rd)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// maxSourceName bounds a rule file name in a compile request.
const maxSourceName = 255

// Serve is the `csm yara-worker` loop on the socket its launcher handed it.
// The same worker compiles (in the short-lived compile unit) and scans (in
// the scan unit): it reads only descriptors it is given, never a path, and
// keeps the rules it loaded for the life of the connection.
func Serve(ctx context.Context, conn *net.UnixConn, eng Engine) error {
	w := &worker{eng: eng}
	return workerproc.Serve(ctx, conn, workerproc.Limits{MaxFrameBytes: yaraipc.MaxFrameBytes, MaxFDs: 1}, w.handle)
}

type worker struct {
	eng   Engine
	rules Rules
}

// fdCount is how many request descriptors each op takes.
var fdCount = map[string]int{
	workerproc.OpHello: 0,
	yaraipc.OpPing:     0,
	yaraipc.OpCompile:  1,
	yaraipc.OpLoad:     1,
	yaraipc.OpScanFD:   1,
}

func (w *worker) handle(_ context.Context, req workerproc.Frame, fds []*os.File) (workerproc.Frame, []*os.File) {
	want, known := fdCount[req.Op]
	if !known {
		return fail("unknown op %q", req.Op)
	}
	if len(fds) != want {
		return fail("%s takes %d descriptors, got %d", req.Op, want, len(fds))
	}
	switch req.Op {
	case workerproc.OpHello:
		return workerproc.HelloReply(yaraipc.ProtocolVersion), nil
	case yaraipc.OpCompile:
		return w.compile(req, fds[0])
	case yaraipc.OpLoad:
		return w.load(fds[0])
	case yaraipc.OpPing:
		if w.rules == nil {
			return fail("no rules loaded")
		}
		return reply(yaraipc.LoadResult{RuleCount: w.rules.Count()}), nil
	default:
		return w.scan(req, fds[0])
	}
}

func (w *worker) compile(req workerproc.Frame, f *os.File) (workerproc.Frame, []*os.File) {
	var args yaraipc.CompileArgs
	if err := decodeArgs(req.Payload, &args); err != nil {
		return fail("compile: %v", err)
	}
	size, err := regularSize(f)
	if err != nil {
		return fail("compile: %v", err)
	}
	if err := checkSpans(args.Sources, size); err != nil {
		return fail("compile: %v", err)
	}
	sources := make([]yara.Source, 0, len(args.Sources))
	var off int64
	for _, span := range args.Sources {
		text := make([]byte, span.Size)
		if _, err := io.ReadFull(io.NewSectionReader(f, off, span.Size), text); err != nil {
			return fail("compile: read %s: %v", span.Name, err)
		}
		off += span.Size
		sources = append(sources, yara.Source{Name: span.Name, Text: text})
	}
	rules, err := w.eng.Compile(sources)
	if err != nil {
		// The operator's rules are broken, not the worker.
		return reply(yaraipc.CompileResult{CompileError: err.Error()}), nil
	}
	var buf bytes.Buffer
	if _, err := rules.WriteTo(&buf); err != nil {
		return fail("compile: serialize: %v", err)
	}
	out, err := yaraipc.SealedMemfd("csm-yara-rules", buf.Bytes())
	if err != nil {
		return fail("compile: %v", err)
	}
	return reply(yaraipc.CompileResult{RuleCount: rules.Count()}), []*os.File{out}
}

// checkSpans requires named spans that exactly cover size bytes.
func checkSpans(spans []yaraipc.SourceSpan, size int64) error {
	if len(spans) == 0 || len(spans) > yaraipc.MaxSources {
		return fmt.Errorf("%d sources, want 1 to %d", len(spans), yaraipc.MaxSources)
	}
	var total int64
	for _, s := range spans {
		if s.Name == "" || len(s.Name) > maxSourceName || strings.ContainsAny(s.Name, "/\x00") {
			return fmt.Errorf("invalid source name %q", s.Name)
		}
		if s.Size < 0 || s.Size > size-total {
			return fmt.Errorf("source %s does not fit the descriptor", s.Name)
		}
		total += s.Size
	}
	if total != size {
		return fmt.Errorf("sources cover %d of %d bytes", total, size)
	}
	return nil
}

func (w *worker) load(f *os.File) (workerproc.Frame, []*os.File) {
	size, err := regularSize(f)
	if err != nil {
		return fail("load: %v", err)
	}
	rules, err := w.eng.Load(io.NewSectionReader(f, 0, size))
	if err != nil {
		return fail("load: %v", err)
	}
	w.rules = rules
	return reply(yaraipc.LoadResult{RuleCount: rules.Count()}), nil
}

func (w *worker) scan(req workerproc.Frame, f *os.File) (workerproc.Frame, []*os.File) {
	if w.rules == nil {
		return fail("no rules loaded")
	}
	var args yaraipc.ScanFDArgs
	if err := decodeArgs(req.Payload, &args); err != nil {
		return fail("scan_fd: %v", err)
	}
	if args.MaxBytes <= 0 {
		return fail("invalid descriptor scan size: %d", args.MaxBytes)
	}
	data, err := io.ReadAll(io.NewSectionReader(f, 0, int64(args.MaxBytes)))
	if err != nil {
		return fail("read descriptor: %v", err)
	}
	if len(data) != args.MaxBytes {
		return fail("read descriptor: got %d of %d bytes", len(data), args.MaxBytes)
	}
	matches, err := w.rules.Scan(data)
	if err != nil {
		return fail("scan: %v", err)
	}
	out := make([]yaraipc.Match, 0, len(matches))
	for _, m := range matches {
		out = append(out, yaraipc.Match{RuleName: m.RuleName, Meta: m.Meta})
	}
	return reply(struct {
		Matches []yaraipc.Match `json:"matches"`
	}{out}), nil
}

func regularSize(f *os.File) (int64, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !st.Mode().IsRegular() {
		return 0, errors.New("descriptor is not a regular file")
	}
	return st.Size(), nil
}

func decodeArgs(payload json.RawMessage, out any) error {
	if len(payload) == 0 {
		return errors.New("empty payload")
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func reply(v any) workerproc.Frame {
	payload, err := json.Marshal(v)
	if err != nil {
		return workerproc.Frame{Error: "marshal reply: " + err.Error()}
	}
	return workerproc.Frame{Payload: payload}
}

func fail(format string, args ...any) (workerproc.Frame, []*os.File) {
	return workerproc.Frame{Error: fmt.Sprintf(format, args...)}, nil
}
