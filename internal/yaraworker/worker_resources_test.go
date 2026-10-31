//go:build linux

package yaraworker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

type resourceRules struct {
	fakeRules
	destroyed int
	writeErr  error
	scanErr   error
	oversize  bool
}

func (r *resourceRules) Destroy() { r.destroyed++ }

func (r *resourceRules) WriteTo(w io.Writer) (int64, error) {
	if r.writeErr != nil {
		return 0, r.writeErr
	}
	if r.oversize {
		n, err := w.Write(make([]byte, yaraipc.MaxSerializedRules+1))
		return int64(n), err
	}
	return r.fakeRules.WriteTo(w)
}

func (r *resourceRules) Scan(data []byte) ([]yara.Match, error) {
	if r.scanErr != nil {
		return nil, r.scanErr
	}
	return r.fakeRules.Scan(data)
}

type resourceEngine struct {
	rules *resourceRules
	err   error
}

func (e *resourceEngine) Compile([]yara.Source) (Rules, error) { return e.rules, e.err }
func (e *resourceEngine) Load(io.Reader) (Rules, error)        { return e.rules, e.err }

func TestWorkerReleasesCompiledRules(t *testing.T) {
	for _, failWrite := range []bool{false, true} {
		rules := &resourceRules{}
		if failWrite {
			rules.writeErr = errors.New("serialization failed")
		}
		w := &worker{eng: &resourceEngine{rules: rules}}
		resp, fds := w.compile(workerproc.Frame{Payload: []byte(`{"sources":[{"name":"a.yar","size":0}]}`)}, memfd(t, ""))
		for _, fd := range fds {
			_ = fd.Close()
		}
		wantFDs := 1
		if failWrite {
			wantFDs = 0
		}
		if (resp.Error != "") != failWrite || len(fds) != wantFDs {
			t.Fatalf("compile = %+v, %d fds", resp, len(fds))
		}
		if rules.destroyed != 1 {
			t.Errorf("compiled rules destroyed %d times, want 1 (write failure: %v)", rules.destroyed, failWrite)
		}
	}
}

func TestWorkerReleasesReplacedRules(t *testing.T) {
	old, next := &resourceRules{}, &resourceRules{}
	eng := &resourceEngine{rules: next, err: errors.New("load failed")}
	w := &worker{eng: eng, rules: old}
	resp, _ := w.load(memfd(t, "compiled"))
	if resp.Error == "" || w.rules != old || old.destroyed != 0 || next.destroyed != 0 {
		t.Fatal("failed load changed the active rules")
	}
	eng.err = nil
	resp, _ = w.load(memfd(t, "compiled"))
	if resp.Error != "" || w.rules != next || old.destroyed != 1 || next.destroyed != 0 {
		t.Fatalf("load = %+v, old destroyed %d times, next destroyed %d times", resp, old.destroyed, next.destroyed)
	}
}

func TestWorkerReleasesRulesOnDisconnect(t *testing.T) {
	rules := &resourceRules{}
	t.Cleanup(func() {
		if rules.destroyed != 1 {
			t.Errorf("loaded rules destroyed %d times, want 1", rules.destroyed)
		}
	})
	c := startWorkerWithEngine(t, &resourceEngine{rules: rules})
	resp, _ := call(t, c, yaraipc.OpLoad, nil, memfd(t, "compiled"))
	if resp.Error != "" {
		t.Fatal(resp.Error)
	}
}

func TestWorkerCompileRejectsOversizeOutput(t *testing.T) {
	w := &worker{eng: &resourceEngine{rules: &resourceRules{oversize: true}}}
	resp, fds := w.compile(workerproc.Frame{Payload: []byte(`{"sources":[{"name":"a.yar","size":0}]}`)}, memfd(t, ""))
	for _, fd := range fds {
		_ = fd.Close()
	}
	var res yaraipc.CompileResult
	if resp.Error != "" || json.Unmarshal(resp.Payload, &res) != nil || res.CompileError == "" || res.RuleCount != 0 || len(fds) != 0 {
		t.Fatalf("oversize serialization accepted or reported as a worker failure: %+v, %d fds", resp, len(fds))
	}
	if !strings.Contains(res.CompileError, "signatures.yara_worker_enabled") {
		t.Fatalf("oversize compile error does not name the way out: %q", res.CompileError)
	}
}

func TestWorkerScanRejectsNonRegularDescriptor(t *testing.T) {
	f, err := os.Open("/dev/zero")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c := loadedWorker(t, "evil")
	resp, fds := call(t, c, yaraipc.OpScanFD, yaraipc.ScanFDArgs{MaxBytes: 4}, f)
	if resp.Error == "" || len(fds) != 0 {
		t.Fatalf("device scanned: %+v, %d fds", resp, len(fds))
	}
}

func TestWorkerScanErrorIsNotClean(t *testing.T) {
	rules := &resourceRules{fakeRules: fakeRules{words: []string{"evil"}}, scanErr: errors.New("scan failed")}
	w := &worker{rules: rules}
	resp, fds := w.scan(workerproc.Frame{Payload: []byte(`{"max_bytes":4}`)}, memfd(t, "evil"))
	if resp.Error == "" || len(resp.Payload) != 0 || len(fds) != 0 {
		t.Fatalf("failed scan returned a result: %+v, %d fds", resp, len(fds))
	}
}

func TestWorkerLongCompileErrorStaysAResult(t *testing.T) {
	eng := &resourceEngine{err: errors.New(strings.Repeat("\x00", yaraipc.MaxFrameBytes/6))}
	w := &worker{eng: eng}
	resp, fds := w.compile(workerproc.Frame{Payload: []byte(`{"sources":[{"name":"bad.yar","size":0}]}`)}, memfd(t, ""))
	var result yaraipc.CompileResult
	decode(t, resp, &result)
	if result.CompileError == "" || result.RuleCount != 0 || len(fds) != 0 {
		t.Fatal("compile failure was not a result")
	}
	if err := workerproc.WriteFrame(io.Discard, resp, yaraipc.MaxFrameBytes); err != nil {
		t.Fatalf("compile error cannot be sent as a result: %v", err)
	}
}

func TestWorkerLongRequestErrorFitsFrame(t *testing.T) {
	req := workerproc.Frame{Op: strings.Repeat("x", yaraipc.MaxFrameBytes-10)}
	if err := workerproc.WriteFrame(io.Discard, req, yaraipc.MaxFrameBytes); err != nil {
		t.Fatalf("request must fit in a frame: %v", err)
	}
	w := &worker{eng: fakeEngine{}}
	resp, fds := w.handle(context.Background(), req, nil)
	if resp.Error == "" || len(fds) != 0 {
		t.Fatal("unknown operation did not fail")
	}
	if err := workerproc.WriteFrame(io.Discard, resp, yaraipc.MaxFrameBytes); err != nil {
		t.Fatalf("request error cannot be sent: %v", err)
	}
}
