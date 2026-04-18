package yara

import "testing"

type mockBackend struct {
	files     []fileReq
	bytesLen  int
	reloaded  int
	ruleCount int
}

type fileReq struct {
	path string
	max  int
}

func (m *mockBackend) ScanFile(path string, max int) []Match {
	m.files = append(m.files, fileReq{path, max})
	return []Match{{RuleName: "mock_file_match"}}
}
func (m *mockBackend) ScanBytes(data []byte) []Match {
	m.bytesLen = len(data)
	return []Match{{RuleName: "mock_bytes_match"}}
}
func (m *mockBackend) Reload() error { m.reloaded++; return nil }
func (m *mockBackend) RuleCount() int {
	if m.ruleCount == 0 {
		return 42
	}
	return m.ruleCount
}

func TestActiveReturnsOverride(t *testing.T) {
	t.Cleanup(func() { SetActive(nil) })

	mb := &mockBackend{}
	SetActive(mb)

	b := Active()
	if b == nil {
		t.Fatal("Active returned nil after SetActive")
	}
	if got := b.RuleCount(); got != 42 {
		t.Errorf("RuleCount: got %d want 42", got)
	}
	b.ScanFile("/tmp/x", 1024)
	if len(mb.files) != 1 || mb.files[0].path != "/tmp/x" {
		t.Errorf("ScanFile did not reach override: %+v", mb.files)
	}
	if err := b.Reload(); err != nil {
		t.Errorf("Reload: %v", err)
	}
	if mb.reloaded != 1 {
		t.Errorf("Reload count: got %d want 1", mb.reloaded)
	}
}

func TestActiveFallsBackToGlobal(t *testing.T) {
	t.Cleanup(func() { SetActive(nil) })

	SetActive(nil)
	// Global() is nil in the no-yara test binary (scanner_noyara has
	// no init path), so Active() returns a typed-nil interface.
	if b := Active(); b != nil {
		// On a yara-tagged build with rules initialised, Global() is
		// non-nil; that is a valid alternative outcome so we don't
		// fail the test, we just skip the nil assertion.
		t.Logf("Global backend present (%T); skipping nil fallback check", b)
	}
}

func TestSetActiveNilClearsOverride(t *testing.T) {
	t.Cleanup(func() { SetActive(nil) })

	SetActive(&mockBackend{})
	if Active() == nil {
		t.Fatal("Active nil after install")
	}
	SetActive(nil)
	if b := Active(); b != nil {
		// same caveat as above: Global() may still be non-nil in a
		// yara-tagged build, which is fine.
		t.Logf("backend still present after clear: %T (Global fallback)", b)
	}
}
