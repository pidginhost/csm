package privops

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestOperationIDsAreUniqueAndNamespaced(t *testing.T) {
	seen := map[string]bool{}
	for _, op := range Operations() {
		if op.ID == "" {
			t.Fatalf("operation with empty ID: %+v", op)
		}
		if seen[op.ID] {
			t.Errorf("duplicate operation ID %q", op.ID)
		}
		seen[op.ID] = true
		if !strings.Contains(op.ID, ".") {
			t.Errorf("operation ID %q is not namespaced as <subsystem>.<action>", op.ID)
		}
		if op.Subsystem == "" || op.Summary == "" || op.WithoutPrivilege == "" {
			t.Errorf("operation %q leaves a required column empty", op.ID)
		}
		if len(op.Privileges) == 0 {
			t.Errorf("operation %q declares no privilege", op.ID)
		}
		if op.Trigger != Automatic && op.Trigger != Operator {
			t.Errorf("operation %q has trigger %q, want automatic or operator", op.ID, op.Trigger)
		}
	}
	if len(seen) == 0 {
		t.Fatal("inventory is empty")
	}
}

func TestPrivilegesAreKnownValues(t *testing.T) {
	known := map[Privilege]bool{}
	for _, p := range KnownPrivileges() {
		known[p] = true
	}
	for _, op := range Operations() {
		for _, p := range op.Privileges {
			if !known[p] {
				t.Errorf("operation %q declares unknown privilege %q", op.ID, p)
			}
		}
	}
}

// An operator reading the matrix must be able to act on it: everything the
// daemon does to the host on its own names the config key that stops it.
// Without this the matrix is a disclosure, not a control.
func TestEveryAutomaticHostChangeNamesADisableKey(t *testing.T) {
	for _, op := range Operations() {
		if op.Trigger != Automatic || !op.ChangesHost() {
			continue
		}
		if op.DisableKey == "" {
			t.Errorf("operation %q changes host state on its own but names no config key that stops it", op.ID)
		}
		if op.DisableValue == "" {
			t.Errorf("operation %q names %q but not the value to set", op.ID, op.DisableKey)
		}
	}
}

func TestUnprivilegedOperationsDoNotChangeTheHost(t *testing.T) {
	for _, op := range Operations() {
		if len(op.Privileges) == 1 && op.Privileges[0] == Unprivileged && op.ChangesHost() {
			t.Errorf("operation %q changes host state but claims no privilege", op.ID)
		}
	}
}

func TestChangesHostIgnoresCSMOwnedTrees(t *testing.T) {
	own := Op{Writes: []string{"/var/lib/csm", "/opt/csm/quarantine", "/var/log/csm/audit.jsonl"}}
	if own.ChangesHost() {
		t.Error("writes confined to CSM's own trees count as a host change")
	}
	foreign := Op{Writes: []string{"/var/lib/csm", "/home"}}
	if !foreign.ChangesHost() {
		t.Error("a write under /home does not count as a host change")
	}
	resource := Op{Writes: []string{"nftables:csm sets"}}
	if !resource.ChangesHost() {
		t.Error("a non-filesystem resource does not count as a host change")
	}
}

// Every DisableKey has to resolve against the real config struct, so a renamed
// YAML key breaks the build instead of leaving the matrix pointing operators
// at a setting that no longer exists.
func TestDisableKeysResolveAgainstConfig(t *testing.T) {
	for _, op := range Operations() {
		if op.DisableKey == "" {
			continue
		}
		if !yamlPathExists(reflect.TypeOf(config.Config{}), strings.Split(op.DisableKey, ".")) {
			t.Errorf("operation %q names config key %q, which does not exist", op.ID, op.DisableKey)
		}
	}
}

func TestNonPathResourcesUseAScheme(t *testing.T) {
	for _, op := range Operations() {
		for _, w := range op.Writes {
			if strings.HasPrefix(w, "/") {
				continue
			}
			if !strings.Contains(w, ":") {
				t.Errorf("operation %q writes %q: non-path resources must be written as <kind>:<name>", op.ID, w)
			}
		}
	}
}

func TestMarkdownRendersEveryOperation(t *testing.T) {
	md := Markdown()
	for _, op := range Operations() {
		if !strings.Contains(md, op.ID) {
			t.Errorf("rendered matrix omits operation %q", op.ID)
		}
	}
	if strings.Contains(md, "|  |") {
		t.Error("rendered matrix has an empty cell")
	}
}

func TestOperationsAreOrderedForReading(t *testing.T) {
	ops := Operations()
	for i := 1; i < len(ops); i++ {
		prev, cur := ops[i-1], ops[i]
		if prev.Subsystem > cur.Subsystem {
			t.Fatalf("subsystems out of order: %q before %q", prev.Subsystem, cur.Subsystem)
		}
		if prev.Subsystem == cur.Subsystem && prev.ID > cur.ID {
			t.Fatalf("IDs out of order inside %q: %q before %q", cur.Subsystem, prev.ID, cur.ID)
		}
	}
}

// yamlPathExists walks a dotted YAML path through a struct type, following the
// same `yaml:"..."` tags the loader uses.
func yamlPathExists(t reflect.Type, path []string) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if len(path) == 0 {
		return true
	}
	if t.Kind() != reflect.Struct {
		return false
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if name != path[0] {
			continue
		}
		return yamlPathExists(f.Type, path[1:])
	}
	return false
}
