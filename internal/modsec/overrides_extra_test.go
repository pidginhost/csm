package modsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteOverridesFailsOnUnwritablePath(t *testing.T) {
	// Directory that does not exist — os.WriteFile fails on the tmp path.
	path := filepath.Join(t.TempDir(), "nonexistent", "overrides.conf")
	err := WriteOverrides(path, []int{900001})
	if err == nil {
		t.Fatal("WriteOverrides to missing dir should error")
	}
	if !strings.Contains(err.Error(), "writing overrides tmp") {
		t.Errorf("unexpected error prefix: %v", err)
	}
}

func TestReadOverridesMissingReturnsNil(t *testing.T) {
	ids, err := ReadOverrides(filepath.Join(t.TempDir(), "missing.conf"))
	if err != nil {
		t.Fatalf("ReadOverrides missing file: %v", err)
	}
	if ids != nil {
		t.Errorf("missing file -> %v, want nil", ids)
	}
}

func TestReadOverridesIgnoresOutOfRangeIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.conf")
	// 899999 is below the valid range, 901000 is above.
	content := overridesHeader +
		"SecRuleRemoveById 899999\n" +
		"SecRuleRemoveById 900500\n" +
		"SecRuleRemoveById 901000\n" +
		"# comment line\n"
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}
	ids, err := ReadOverrides(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != 900500 {
		t.Errorf("ids = %v, want [900500]", ids)
	}
}

func TestReadOverridesRawMissingReturnsNil(t *testing.T) {
	if got := ReadOverridesRaw(filepath.Join(t.TempDir(), "never.conf")); got != nil {
		t.Errorf("missing file -> %v, want nil", got)
	}
}

func TestReadOverridesRawRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overrides.conf")
	raw := []byte(overridesHeader + "SecRuleRemoveById 900123\n")
	if err := os.WriteFile(path, raw, 0640); err != nil {
		t.Fatal(err)
	}
	got := ReadOverridesRaw(path)
	if string(got) != string(raw) {
		t.Errorf("ReadOverridesRaw mismatch:\ngot:  %q\nwant: %q", got, raw)
	}
}

func TestRestoreOverridesNilContentRemovesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overrides.conf")
	if err := os.WriteFile(path, []byte("existing"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := RestoreOverrides(path, nil); err != nil {
		t.Fatalf("RestoreOverrides(nil): %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file should be gone after RestoreOverrides(nil), stat err=%v", err)
	}
}

func TestRestoreOverridesWritesBytesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overrides.conf")
	content := []byte(overridesHeader + "SecRuleRemoveById 900777\n")
	if err := RestoreOverrides(path, content); err != nil {
		t.Fatalf("RestoreOverrides: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Errorf("content mismatch:\ngot:  %q\nwant: %q", got, content)
	}
	// Temp file should not be left behind.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("leftover .tmp file: %v", err)
	}
}

func TestRestoreOverridesFailsOnUnwritablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope", "overrides.conf")
	err := RestoreOverrides(path, []byte("data"))
	if err == nil {
		t.Fatal("RestoreOverrides to non-existent dir should error")
	}
}

func TestEnsureOverridesIncludeAddsDirectiveAndCreatesFile(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "modsec_rules.conf")
	overridesFile := filepath.Join(dir, "csm_overrides.conf")

	// Seed an existing rules file with some content.
	initial := "SecRule REQUEST_HEADERS:User-Agent \"bad\" \"id:100,deny\"\n"
	if err := os.WriteFile(rulesFile, []byte(initial), 0640); err != nil {
		t.Fatal(err)
	}

	EnsureOverridesInclude(rulesFile, overridesFile)

	got, err := os.ReadFile(rulesFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "Include "+overridesFile) {
		t.Errorf("Include directive missing from rules file:\n%s", got)
	}
	if !strings.HasPrefix(string(got), initial) {
		t.Errorf("original content lost:\n%s", got)
	}

	overridesContent, err := os.ReadFile(overridesFile)
	if err != nil {
		t.Fatalf("overrides file not created: %v", err)
	}
	if !strings.HasPrefix(string(overridesContent), "# CSM ModSecurity Rule Overrides") {
		t.Errorf("overrides file missing header:\n%s", overridesContent)
	}
}

func TestEnsureOverridesIncludeIdempotent(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "modsec_rules.conf")
	overridesFile := filepath.Join(dir, "csm_overrides.conf")

	if err := os.WriteFile(rulesFile, []byte("base\n"), 0640); err != nil {
		t.Fatal(err)
	}
	EnsureOverridesInclude(rulesFile, overridesFile)
	EnsureOverridesInclude(rulesFile, overridesFile) // second call no-op

	got, err := os.ReadFile(rulesFile)
	if err != nil {
		t.Fatal(err)
	}
	if c := strings.Count(string(got), "Include "+overridesFile); c != 1 {
		t.Errorf("Include directive appears %d times, want 1", c)
	}
}

func TestEnsureOverridesIncludeMissingRulesFileIsNoOp(t *testing.T) {
	// Should not panic or create files for missing rules file.
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "does-not-exist.conf")
	overridesFile := filepath.Join(dir, "csm_overrides.conf")
	EnsureOverridesInclude(rulesFile, overridesFile)
	if _, err := os.Stat(overridesFile); !os.IsNotExist(err) {
		t.Errorf("overrides file should not be created when rules file missing")
	}
}

func TestEnsureOverridesIncludePreservesExistingOverridesFile(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "modsec_rules.conf")
	overridesFile := filepath.Join(dir, "csm_overrides.conf")

	if err := os.WriteFile(rulesFile, []byte("base\n"), 0640); err != nil {
		t.Fatal(err)
	}
	custom := []byte("# hand-edited content\nSecRuleRemoveById 900123\n")
	if err := os.WriteFile(overridesFile, custom, 0640); err != nil {
		t.Fatal(err)
	}

	EnsureOverridesInclude(rulesFile, overridesFile)

	got, err := os.ReadFile(overridesFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(custom) {
		t.Errorf("existing overrides file was overwritten:\ngot:  %q\nwant: %q", got, custom)
	}
}
