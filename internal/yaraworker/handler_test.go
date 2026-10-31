package yaraworker

import (
	"errors"
	"testing"

	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

type fakeScanner struct {
	bytesMatches []yara.Match
	bytesErr     error
	reloadErr    error
	ruleCount    int

	bytesCalls  [][]byte
	reloadCalls int
}

func (f *fakeScanner) ScanBytesChecked(data []byte) ([]yara.Match, error) {
	f.bytesCalls = append(f.bytesCalls, append([]byte(nil), data...))
	if f.bytesErr != nil {
		return nil, f.bytesErr
	}
	return f.bytesMatches, nil
}

func (f *fakeScanner) Reload() error {
	f.reloadCalls++
	return f.reloadErr
}

func (f *fakeScanner) RuleCount() int { return f.ruleCount }

func TestHandlerForwardsMatchMetadata(t *testing.T) {
	// The emailav adapter reads match metadata (e.g. "severity") from
	// the IPC match. If the handler ever drops the field during the
	// yara.Match -> yaraipc.Match conversion, emailav silently falls
	// back to its default severity for every rule — this guards that.
	s := &fakeScanner{ruleCount: 1, bytesMatches: []yara.Match{{
		RuleName: "mal_doc",
		Meta:     map[string]string{"severity": "critical", "author": "forge"},
	}}}
	h := NewHandler(s)

	res, err := h.ScanFD(scanFDPart(t), yaraipc.ScanFDArgs{MaxBytes: 1, EmptyRulesClean: true})
	if err != nil {
		t.Fatalf("ScanFD: %v", err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(res.Matches))
	}
	if res.Matches[0].Meta["severity"] != "critical" {
		t.Errorf(`Meta["severity"] = %q`, res.Matches[0].Meta["severity"])
	}
	if res.Matches[0].Meta["author"] != "forge" {
		t.Errorf(`Meta["author"] = %q`, res.Matches[0].Meta["author"])
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

	sres, err := h.ScanFD(scanFDPart(t), yaraipc.ScanFDArgs{MaxBytes: 1, EmptyRulesClean: true})
	if err != nil {
		t.Fatalf("byte scan: %v", err)
	}
	if len(sres.Matches) != 0 {
		t.Errorf("expected zero matches from nil scanner, got %+v", sres.Matches)
	}

	if _, err := h.Reload(yaraipc.ReloadArgs{}); err != nil {
		t.Errorf("Reload on nil scanner should be a no-op, got %v", err)
	}
}
