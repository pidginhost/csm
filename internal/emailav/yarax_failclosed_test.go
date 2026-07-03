//go:build yara

package emailav

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

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
	v, err := s.Scan(tmp)
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
