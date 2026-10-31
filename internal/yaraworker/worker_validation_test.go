//go:build linux

package yaraworker

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/workerproc"
	"github.com/pidginhost/csm/internal/yaraipc"
)

func TestWorkerRejectsUnexpectedPayloads(t *testing.T) {
	for _, op := range []string{yaraipc.OpLoad, yaraipc.OpPing, workerproc.OpHello} {
		t.Run(op, func(t *testing.T) {
			c := loadedWorker(t, "evil")
			var fds []*os.File
			if op == yaraipc.OpLoad {
				fds = append(fds, memfd(t, fakeRulesHeader+"other"))
			}
			resp, out := call(t, c, op, map[string]any{"path": "unexpected.yar"}, fds...)
			if resp.Error == "" || len(out) != 0 {
				t.Fatalf("unexpected payload accepted: %+v, %d fds", resp, len(out))
			}
			resp, _ = call(t, c, yaraipc.OpScanFD, yaraipc.ScanFDArgs{MaxBytes: 4}, memfd(t, "evil"))
			matches, err := yaraipc.DecodeScanReply(resp.Payload)
			if resp.Error != "" || err != nil || len(matches) != 1 || matches[0].RuleName != "evil" {
				t.Fatalf("rejected request changed loaded rules: %+v, %v", resp, err)
			}
		})
	}
}

func TestWorkerRejectsResponseEnvelope(t *testing.T) {
	w := &worker{eng: fakeEngine{}, rules: &fakeRules{words: []string{"evil"}}}
	resp, fds := w.handle(context.Background(), workerproc.Frame{Op: yaraipc.OpPing, Error: "not a request"}, nil)
	if resp.Error == "" || len(fds) != 0 {
		t.Fatalf("response envelope accepted: %+v", resp)
	}
}

func TestDecodeArgsRejectsMalformed(t *testing.T) {
	for _, tc := range []struct {
		payload string
		out     any
	}{
		{`null`, new(yaraipc.ScanFDArgs)},
		{"\v{\"max_bytes\":4}\v", new(yaraipc.ScanFDArgs)},
		{`{"max_bytes":4} {"max_bytes":5}`, new(yaraipc.ScanFDArgs)},
		{`{"max_bytes":4} garbage`, new(yaraipc.ScanFDArgs)},
		{"{\"sources\":[{\"name\":\"\xff\",\"size\":0}]}", new(yaraipc.CompileArgs)},
	} {
		if err := decodeArgs(json.RawMessage(tc.payload), tc.out); err == nil {
			t.Errorf("accepted malformed args: %q", tc.payload)
		}
	}
}

func TestWorkerLoadRejectsOversizeRules(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "rules"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(fakeRulesHeader); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(yaraipc.MaxSerializedRules + 1); err != nil {
		t.Fatal(err)
	}
	c := loadedWorker(t, "evil")
	resp, fds := call(t, c, yaraipc.OpLoad, nil, f)
	if resp.Error == "" || len(fds) != 0 {
		t.Fatalf("oversize rules accepted: %+v, %d fds", resp, len(fds))
	}
	resp, _ = call(t, c, yaraipc.OpPing, nil)
	var ping yaraipc.LoadResult
	decode(t, resp, &ping)
	if ping.RuleCount != 1 {
		t.Fatalf("rejected load changed rule count to %d", ping.RuleCount)
	}
}

func TestCheckSpansOverflowAndCoverage(t *testing.T) {
	for _, tc := range []struct {
		name  string
		size  int64
		spans []yaraipc.SourceSpan
		valid bool
	}{
		{"exact", 3, []yaraipc.SourceSpan{{Name: "a", Size: 1}, {Name: "b", Size: 2}}, true},
		{"empty source", 0, []yaraipc.SourceSpan{{Name: "a"}}, true},
		{"int64 boundary", math.MaxInt64, []yaraipc.SourceSpan{{Name: "a", Size: math.MaxInt64}}, true},
		{"overflow", math.MaxInt64, []yaraipc.SourceSpan{{Name: "a", Size: math.MaxInt64}, {Name: "b", Size: 1}}, false},
		{"past end", 3, []yaraipc.SourceSpan{{Name: "a", Size: 2}, {Name: "b", Size: 2}}, false},
		{"uncovered", 3, []yaraipc.SourceSpan{{Name: "a", Size: 2}}, false},
		{"negative descriptor", -1, []yaraipc.SourceSpan{{Name: "a"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkSpans(tc.spans, tc.size); (err == nil) != tc.valid {
				t.Fatalf("checkSpans = %v, valid = %v", err, tc.valid)
			}
		})
	}
}

func TestWorkerHelloValidatesVersion(t *testing.T) {
	c := startWorker(t)
	for _, version := range []int{0, yaraipc.ProtocolVersion + 1, yaraipc.ProtocolVersion} {
		resp, fds := call(t, c, workerproc.OpHello, workerproc.Hello{Protocol: version})
		if len(fds) != 0 {
			t.Fatal("hello returned descriptors")
		}
		if version != yaraipc.ProtocolVersion {
			if resp.Error == "" {
				t.Errorf("hello accepted version %d", version)
			}
			continue
		}
		var hello workerproc.Hello
		decode(t, resp, &hello)
		if hello.Protocol != version {
			t.Fatalf("hello version = %d, want %d", hello.Protocol, version)
		}
	}
}
