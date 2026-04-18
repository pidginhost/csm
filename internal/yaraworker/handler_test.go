package yaraworker

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

type fakeScanner struct {
	fileMatches  []yara.Match
	bytesMatches []yara.Match
	reloadErr    error
	ruleCount    int

	fileCalls   []fileCall
	bytesCalls  [][]byte
	reloadCalls int
}

type fileCall struct {
	path     string
	maxBytes int
}

func (f *fakeScanner) ScanFile(path string, maxBytes int) []yara.Match {
	f.fileCalls = append(f.fileCalls, fileCall{path, maxBytes})
	return f.fileMatches
}

func (f *fakeScanner) ScanBytes(data []byte) []yara.Match {
	f.bytesCalls = append(f.bytesCalls, append([]byte(nil), data...))
	return f.bytesMatches
}

func (f *fakeScanner) Reload() error {
	f.reloadCalls++
	return f.reloadErr
}

func (f *fakeScanner) RuleCount() int { return f.ruleCount }

func TestHandlerScanFileConvertsMatches(t *testing.T) {
	s := &fakeScanner{fileMatches: []yara.Match{{RuleName: "r1"}, {RuleName: "r2"}}}
	h := NewHandler(s)

	res, err := h.ScanFile(yaraipc.ScanFileArgs{Path: "/tmp/x", MaxBytes: 8192})
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(res.Matches) != 2 || res.Matches[0].RuleName != "r1" || res.Matches[1].RuleName != "r2" {
		t.Errorf("matches: got %+v", res.Matches)
	}
	if len(s.fileCalls) != 1 || s.fileCalls[0].path != "/tmp/x" || s.fileCalls[0].maxBytes != 8192 {
		t.Errorf("scanner call: got %+v", s.fileCalls)
	}
}

func TestHandlerScanBytesPassesThrough(t *testing.T) {
	s := &fakeScanner{bytesMatches: []yara.Match{{RuleName: "webshell"}}}
	h := NewHandler(s)

	payload := []byte("anything")
	res, err := h.ScanBytes(yaraipc.ScanBytesArgs{Data: payload})
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	if len(res.Matches) != 1 || res.Matches[0].RuleName != "webshell" {
		t.Errorf("matches: got %+v", res.Matches)
	}
	if len(s.bytesCalls) != 1 || string(s.bytesCalls[0]) != string(payload) {
		t.Errorf("scanner saw wrong payload: %q", s.bytesCalls[0])
	}
}

func TestHandlerReloadSurfacesError(t *testing.T) {
	s := &fakeScanner{reloadErr: errors.New("bad rule at line 42")}
	h := NewHandler(s)

	_, err := h.Reload(yaraipc.ReloadArgs{})
	if err == nil || err.Error() != "bad rule at line 42" {
		t.Fatalf("expected reload error, got %v", err)
	}
	if s.reloadCalls != 1 {
		t.Errorf("reload calls: got %d want 1", s.reloadCalls)
	}
}

func TestHandlerReloadReturnsRuleCount(t *testing.T) {
	s := &fakeScanner{ruleCount: 57}
	h := NewHandler(s)

	res, err := h.Reload(yaraipc.ReloadArgs{})
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if res.RuleCount != 57 {
		t.Errorf("rule_count: got %d want 57", res.RuleCount)
	}
}

func TestHandlerPingReportsRuleCount(t *testing.T) {
	s := &fakeScanner{ruleCount: 100}
	h := NewHandler(s)

	res, err := h.Ping()
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !res.Alive {
		t.Error("alive: got false, want true")
	}
	if res.RuleCount != 100 {
		t.Errorf("rule_count: got %d want 100", res.RuleCount)
	}
}

func TestHandlerNilScannerIsAlive(t *testing.T) {
	// Mirrors the !yara build: no scanner, handler still responds.
	h := NewHandler(nil)

	res, err := h.Ping()
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !res.Alive {
		t.Error("alive: got false, want true")
	}
	if res.RuleCount != 0 {
		t.Errorf("rule_count: got %d want 0", res.RuleCount)
	}

	sres, err := h.ScanFile(yaraipc.ScanFileArgs{Path: "/tmp/x"})
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(sres.Matches) != 0 {
		t.Errorf("expected zero matches from nil scanner, got %+v", sres.Matches)
	}

	if _, err := h.Reload(yaraipc.ReloadArgs{}); err != nil {
		t.Errorf("Reload on nil scanner should be a no-op, got %v", err)
	}
}
