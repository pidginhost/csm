package modsec

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryMetadataUsesOnlyRuleActions(t *testing.T) {
	dir := t.TempDir()
	const rules = `SecRule ARGS "@rx msg:'anomaly',tag:'attack-sqli'" "id:1001,deny,msg:'Custom hit %{MATCHED_VAR}',tag:'application-multi',tag:'%{TX.sqli_score}'"
SecRule ARGS "@rx x" "id:1002,deny,chain,msg:'Policy, not allowed by policy',tag:'policy'"
SecRule ARGS "@rx x" "msg:'SQL injection',tag:'attack-sqli'"
SecRule ARGS "@rx x" "id:1003,log,msg:'SQL injection',tag:'attack-sqli',tag:'application-multi'"
SecRule ARGS "@rx x" "id:1004,deny,msg:'It\\'s a custom hit',logdata:'tag:attack-sqli'"
`
	if err := os.WriteFile(filepath.Join(dir, "rules.conf"), []byte(rules), 0600); err != nil {
		t.Fatal(err)
	}
	reg, err := BuildRegistry([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[int]RuleMetadata{
		1001: {Message: "Custom hit  ", Tags: "application-multi  "},
		1002: {Message: "Policy, not allowed by policy", Tags: "policy"},
		1003: {Message: "SQL injection", Tags: "attack-sqli application-multi"},
		1004: {Message: "It's a custom hit"},
	} {
		if got, ok := reg.Metadata(id); !ok || got != want {
			t.Errorf("Metadata(%d) = %+v, %v; want %+v, true", id, got, ok, want)
		}
	}
	if _, ok := reg.Action(1003); ok {
		t.Fatal("metadata-only rule acquired a disposition")
	}
	if got, ok := reg.Metadata(9999); ok || got != (RuleMetadata{}) {
		t.Errorf("missing metadata = %+v, %v", got, ok)
	}
	if got, ok := (*Registry)(nil).Metadata(1001); ok || got != (RuleMetadata{}) {
		t.Errorf("nil metadata = %+v, %v", got, ok)
	}
}

func TestRegistryMetadataFollowsActionPrecedence(t *testing.T) {
	first, fallback := t.TempDir(), t.TempDir()
	for _, file := range []struct{ dir, name, rules string }{
		{first, "a.conf", `SecRule ARGS "x" "id:1001,deny,msg:'SQL injection',tag:'attack-sqli'"`},
		{first, "b.conf", `SecRule ARGS "x" "id:1001,log,msg:'Custom hit'"`},
		{fallback, "rules.conf", `SecRule ARGS "x" "id:1001,deny,msg:'Inbound anomaly score exceeded'"`},
	} {
		if err := os.WriteFile(filepath.Join(file.dir, file.name), []byte(file.rules), 0600); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := BuildRegistry([]string{first, fallback})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := reg.Metadata(1001); !ok || got != (RuleMetadata{Message: "Custom hit"}) {
		t.Fatalf("overridden metadata = %+v, %v", got, ok)
	}
	if _, ok := reg.Action(1001); ok {
		t.Fatal("overridden action survived")
	}
}

func TestRegistryMetadataDoesNotUseUnreadFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	writeRule(t, path, `SecRule ARGS "x" "id:1001,deny,msg:'Anomaly score exceeded'"`)
	readErr := errors.New("rule read failed")
	interceptRuleReads(t, path, func(f *os.File) io.Reader {
		return ruleReadFunc(func(p []byte) (int, error) {
			n, _ := f.Read(p)
			return n, readErr
		})
	})
	reg, err := BuildRegistry([]string{dir})
	if !errors.Is(err, readErr) {
		t.Fatalf("BuildRegistry error = %v, want read failure", err)
	}
	if got, ok := reg.Metadata(1001); ok || got != (RuleMetadata{}) {
		t.Fatalf("failed read authorized metadata: %+v, %v", got, ok)
	}
}

func TestRegistryMetadataSnapshotsDoNotChangeOnReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	writeRule(t, path, `SecRule ARGS "x" "id:1001,deny,msg:'SQL injection'"`)
	old, err := BuildRegistry([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	writeRule(t, path, `SecRule ARGS "x" "id:1001,pass,msg:'Policy anomaly'"`)
	next, err := BuildRegistry([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	previous := Global()
	t.Cleanup(func() { SetGlobal(previous) })
	SetGlobal(old)
	if !ReplaceGlobal(next) {
		t.Fatal("new metadata snapshot was refused")
	}
	if m, ok := Global().Metadata(1001); !ok || m.Message != "Policy anomaly" {
		t.Fatalf("new metadata not visible: %+v, %v", m, ok)
	}
	if m, ok := old.Metadata(1001); !ok || m.Message != "SQL injection" {
		t.Fatalf("reader of old snapshot changed: %+v, %v", m, ok)
	}
	if old.Fingerprint() == next.Fingerprint() {
		t.Fatal("metadata change did not invalidate the registry fingerprint")
	}
}
