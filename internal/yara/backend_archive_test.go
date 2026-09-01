package yara

import "testing"

// alwaysMatchBackend stands in for the out-of-process IPC worker: it reports a
// match for any bytes and does NOT run the *Scanner method. The package-level
// ScanBytesChecked must apply the archive policy itself so it holds under
// every backend, not just the in-process one used by tests.
type alwaysMatchBackend struct{}

func (alwaysMatchBackend) ScanFile(string, int) []Match { return []Match{{RuleName: "x"}} }
func (alwaysMatchBackend) ScanBytes([]byte) []Match     { return []Match{{RuleName: "x"}} }
func (alwaysMatchBackend) ScanBytesChecked([]byte) ([]Match, error) {
	return []Match{{RuleName: "x"}}, nil
}
func (alwaysMatchBackend) RuleCount() int { return 1 }
func (alwaysMatchBackend) Reload() error  { return nil }

func TestPackageScanBytesCheckedSkipsArchivesByNameAndMagic(t *testing.T) {
	zip := append([]byte{'P', 'K', 0x03, 0x04}, []byte("<?php eval($_POST['x']); system($_GET['c']);")...)
	if got := len(scanBytesCheckedMust(t, alwaysMatchBackend{}, "/home/u/backups/plugin.zip", zip)); got != 0 {
		t.Errorf("archive by name and magic must be skipped at the package layer regardless of backend, got %d matches", got)
	}
	// The same bytes under an executable name are a polyglot webshell, not an
	// archive, and must reach the backend.
	if got := len(scanBytesCheckedMust(t, alwaysMatchBackend{}, "/home/u/public_html/x.php", zip)); got != 1 {
		t.Errorf("zip-prefixed .php must dispatch to backend, got %d matches", got)
	}
	// Plain PHP under any name still reaches the backend.
	if got := len(scanBytesCheckedMust(t, alwaysMatchBackend{}, "/home/u/public_html/x.php", []byte("<?php system($_POST['c']);"))); got != 1 {
		t.Errorf("non-archive must dispatch to backend, got %d matches", got)
	}
}

func scanBytesCheckedMust(t *testing.T, b Backend, name string, data []byte) []Match {
	t.Helper()
	m, err := ScanBytesChecked(b, name, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return m
}
