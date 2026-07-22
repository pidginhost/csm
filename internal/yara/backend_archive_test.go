package yara

import "testing"

// alwaysMatchBackend stands in for the out-of-process IPC worker: it reports a
// match for any bytes and, crucially, does NOT run the *Scanner method where
// the archive guard also lives. The package-level ScanBytesChecked must skip
// archives itself so the guard applies under every backend, not just the
// in-process one used by tests.
type alwaysMatchBackend struct{}

func (alwaysMatchBackend) ScanFile(string, int) []Match          { return []Match{{RuleName: "x"}} }
func (alwaysMatchBackend) ScanBytes([]byte) []Match              { return []Match{{RuleName: "x"}} }
func (alwaysMatchBackend) ScanBytesChecked([]byte) ([]Match, error) { return []Match{{RuleName: "x"}}, nil }
func (alwaysMatchBackend) RuleCount() int                        { return 1 }
func (alwaysMatchBackend) Reload() error                         { return nil }

func TestPackageScanBytesCheckedSkipsArchives(t *testing.T) {
	zip := append([]byte{'P', 'K', 0x03, 0x04}, []byte("<?php eval($_POST['x']); system($_GET['c']);")...)
	hits, err := ScanBytesChecked(alwaysMatchBackend{}, zip)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hits) != 0 {
		t.Errorf("archive must be skipped at the package layer regardless of backend, got %d matches", len(hits))
	}
	// A non-archive payload must still reach the backend.
	if got := len(ScanBytesCheckedMust(t, alwaysMatchBackend{}, []byte("<?php system($_POST['c']);"))); got != 1 {
		t.Errorf("non-archive must dispatch to backend, got %d matches", got)
	}
}

func ScanBytesCheckedMust(t *testing.T, b Backend, data []byte) []Match {
	t.Helper()
	m, err := ScanBytesChecked(b, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return m
}
