package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

type forgeFakeBackend struct {
	reloadErr error
	count     int
	reloads   int
}

func (f *forgeFakeBackend) Reload() error  { f.reloads++; return f.reloadErr }
func (f *forgeFakeBackend) RuleCount() int { return f.count }

// A Forge tier that compiles alone but fails the merged reload used to stay
// on disk with a stderr line only: the live rules survived, but the next
// worker restart compiled the same directory, failed, and ran with zero
// rules until an operator deleted the file by hand. A failed merged reload
// is rolled back and alerted exactly like a rule-count collapse.
func TestSettleForgeInstallRollsBackWhenMergedReloadFails(t *testing.T) {
	rulesDir := t.TempDir()
	forgeFile := filepath.Join(rulesDir, "yara-forge-core.yar")
	if err := os.WriteFile(forgeFile, []byte("rule forge_conflict { condition: true }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := New(&config.Config{}, nil, nil, "")
	backend := &forgeFakeBackend{reloadErr: errors.New("duplicate identifier forge_conflict"), count: 0}

	if ok := d.settleForgeInstall(backend, forgeFile, 5000); ok {
		t.Fatal("failed merged reload reported as a settled install")
	}
	if _, err := os.Stat(forgeFile); !os.IsNotExist(err) {
		t.Fatalf("non-compiling tier left on disk: %v", err)
	}
	if backend.reloads < 2 {
		t.Fatalf("backend reloaded %d time(s); the rollback must reload after removing the file", backend.reloads)
	}
	select {
	case f := <-d.alertCh:
		if f.Check != "yara_forge_rollback" || f.Severity != alert.Critical {
			t.Fatalf("finding = %s/%s, want yara_forge_rollback/Critical", f.Check, f.Severity)
		}
	default:
		t.Fatal("no rollback finding emitted")
	}
}

// The count-collapse rollback keeps its behaviour under the shared path.
func TestSettleForgeInstallRollsBackOnCountCollapse(t *testing.T) {
	rulesDir := t.TempDir()
	forgeFile := filepath.Join(rulesDir, "yara-forge-core.yar")
	if err := os.WriteFile(forgeFile, []byte("rule x { condition: true }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := New(&config.Config{}, nil, nil, "")
	backend := &forgeFakeBackend{count: 146}
	if ok := d.settleForgeInstall(backend, forgeFile, 5227); ok {
		t.Fatal("count collapse reported as settled")
	}
	if _, err := os.Stat(forgeFile); !os.IsNotExist(err) {
		t.Fatalf("collapsed tier left on disk: %v", err)
	}
}
