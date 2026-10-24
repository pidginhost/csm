//go:build yara

package emailav

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	emime "github.com/pidginhost/csm/internal/mime"
	"github.com/pidginhost/csm/internal/yara"
)

// A scan that could not complete (worker down, attachment too large for one
// IPC frame, transport error) must fail closed: the adapter returns an error
// so the orchestrator records the engine as errored, instead of a false
// "clean" verdict that lets an infected attachment through.
func TestYaraXScannerFailsClosedOnScanError(t *testing.T) {
	b := &checkedErrBackend{ruleCount: 1, err: errors.New("frame length 17000000 exceeds cap 16777216")}
	s := NewYaraXScanner(b)
	tmp := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(tmp, []byte("infected-but-too-big-to-scan"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := s.Scan(openPart(t, tmp))
	if err == nil {
		t.Fatalf("scan error must surface, got clean verdict %+v", v)
	}
	if v.Infected {
		t.Errorf("errored scan must not report a verdict, got %+v", v)
	}
}

// checkedErrBackend is a healthy backend whose checked scan fails. It
// implements yara.CheckedScanner so the adapter routes through the
// error-returning path.
type checkedErrBackend struct {
	ruleCount int
	err       error
}

func (b *checkedErrBackend) ScanFile(string, int) []yara.Match { return nil }
func (b *checkedErrBackend) ScanBytes([]byte) []yara.Match     { return nil }
func (b *checkedErrBackend) ScanBytesChecked([]byte) ([]yara.Match, error) {
	return nil, b.err
}
func (b *checkedErrBackend) Reload() error  { return nil }
func (b *checkedErrBackend) RuleCount() int { return b.ruleCount }

// A YARA worker that is down when a mail part reaches it must leave the
// engine errored, never a clean verdict for the part.
func TestYaraScanFDWorkerDownIsEngineError(t *testing.T) {
	b := &fdErrBackend{checkedErrBackend{ruleCount: 1, err: errors.New("yaraworker: supervisor not running")}}
	o := NewOrchestrator([]Scanner{NewYaraXScanner(b)}, 5*time.Second)
	p := partFile(t, "payload")
	res := o.ScanParts("msg", []emime.ExtractedPart{{Filename: "x.bin", Size: p.Size, File: p.File}}, false)
	if res.Infected || !slices.Contains(res.ErroredEngines, "yara-x") {
		t.Fatalf("worker down must error the engine, got %+v", res)
	}
}

// fdErrBackend takes descriptors, as the YARA worker supervisor does, and
// fails every descriptor scan.
type fdErrBackend struct{ checkedErrBackend }

func (b *fdErrBackend) ScanFDChecked(*os.File, int64) ([]yara.Match, error) { return nil, b.err }

func TestYaraIncompletePartIsEngineError(t *testing.T) {
	b := &fakeBackend{ruleCount: 1}
	o := NewOrchestrator([]Scanner{NewYaraXScanner(b)}, 5*time.Second)
	p := partFile(t, "part")
	res := o.ScanParts("msg", []emime.ExtractedPart{{Filename: "part", File: p.File, Size: p.Size + 1}}, false)
	if res.Infected || !slices.Equal(res.ErroredEngines, []string{"yara-x"}) || len(res.TimedOutEngines) != 0 || len(b.scanned) != 0 {
		t.Fatalf("incomplete scan must error before scanning, got %+v, scanned %q", res, b.scanned)
	}
}
