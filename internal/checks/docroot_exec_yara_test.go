//go:build yara

package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/yara"
)

func TestInspectDocrootExecRechecksReloadedRules(t *testing.T) {
	f := newDocrootExecFixture(t)
	path := f.write(t, "tool", testELFHeader+"payload-fetcher")
	f.procs[705] = path
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "test.yar")
	if err := os.WriteFile(rulePath, []byte(`rule test_rule { condition: false }`), 0600); err != nil {
		t.Fatal(err)
	}
	backend, err := yara.NewScanner(dir)
	if err != nil {
		t.Fatal(err)
	}
	activeYARABackend = func() yara.Backend { return backend }
	if got := InspectDocrootExec(nil, 705, 1001, path, "bash", f.roots); got != nil {
		t.Fatalf("initial rules: %+v", got)
	}
	if err = os.WriteFile(rulePath, []byte(`rule test_rule { meta: severity = "critical" condition: true }`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = backend.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := InspectDocrootExec(nil, 705, 1001, path, "bash", f.roots); got == nil || got.Severity != alert.Critical {
		t.Fatalf("same-count rule reload retained a clean verdict: %+v", got)
	}
}
