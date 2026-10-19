package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/antispam/learn"
	csmstore "github.com/pidginhost/csm/internal/store"
)

func writeLearningTree(t *testing.T, dir, prefix string) {
	t.Helper()
	for name, content := range map[string]string{"keys/prefix": prefix, "anchors/1": "From: a@example.com\r\n\r\nanchor"} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBackupIncludesLearningDir(t *testing.T) {
	dir := t.TempDir()
	learning := filepath.Join(dir, "learning")
	writeLearningTree(t, learning, "csmfz_old")
	out := filepath.Join(dir, "backup.tar.gz")
	if err := WriteBackupArchive(out, BackupSources{LearningDir: learning}); err != nil {
		t.Fatal(err)
	}
	got := tarNames(t, out)
	for _, want := range []string{"antispam/learning/keys/prefix", "antispam/learning/anchors/1"} {
		if !got[want] {
			t.Fatalf("expected %s in archive, got %v", want, got)
		}
	}
}

func bindLedger(t *testing.T, stateDir string) {
	t.Helper()
	db, err := csmstore.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := learn.Open(db).Bind("gen-old", "csmfz_old"); err != nil {
		t.Fatal(err)
	}
}

func declaredRestore(t *testing.T, stateDir string) bool {
	t.Helper()
	db, err := csmstore.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	held, err := learn.Open(db).DeclaredRestore()
	if err != nil {
		t.Fatal(err)
	}
	return held
}

func TestRestoreMarksDeclaredRestore(t *testing.T) {
	dir := t.TempDir()
	srcState, srcLearning := filepath.Join(dir, "src/state"), filepath.Join(dir, "src/learning")
	if err := os.MkdirAll(srcState, 0o700); err != nil {
		t.Fatal(err)
	}
	bindLedger(t, srcState)
	writeLearningTree(t, srcLearning, "csmfz_old")
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := WriteBackupArchive(archive, BackupSources{StateDir: srcState, LearningDir: srcLearning}); err != nil {
		t.Fatal(err)
	}
	dstState, dstLearning := filepath.Join(dir, "dst/state"), filepath.Join(dir, "dst/antispam/learning")
	if err := os.MkdirAll(dstState, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLearningTree(t, dstLearning, "csmfz_current")
	if err := RestoreBackupArchive(archive, BackupSources{StateDir: dstState, LearningDir: dstLearning}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dstLearning, "keys/prefix"))
	if err != nil || string(data) != "csmfz_old" {
		t.Fatalf("restored prefix %q, %v", data, err)
	}
	if info, statErr := os.Stat(filepath.Join(dstLearning, "anchors/1")); statErr != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("restored anchor mode %v, %v", info, statErr)
	}
	if info, statErr := os.Stat(filepath.Join(dstLearning, "keys")); statErr != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("restored keys directory mode %v, %v", info, statErr)
	}
	kept, _ := filepath.Glob(dstLearning + ".old-*")
	if len(kept) != 1 {
		t.Fatalf("replaced learning state not kept aside: %v", kept)
	}
	if data, err = os.ReadFile(filepath.Join(kept[0], "keys/prefix")); err != nil || string(data) != "csmfz_current" {
		t.Fatalf("kept prefix %q, %v", data, err)
	}
	if !declaredRestore(t, dstState) {
		t.Fatal("restored learning state is not marked as a declared restore")
	}
}

func TestRestoreWithoutLearningLeavesNoMark(t *testing.T) {
	dir := t.TempDir()
	srcState := filepath.Join(dir, "src/state")
	if err := os.MkdirAll(srcState, 0o700); err != nil {
		t.Fatal(err)
	}
	createBackupTestDB(t, srcState)
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := WriteBackupArchive(archive, BackupSources{StateDir: srcState}); err != nil {
		t.Fatal(err)
	}
	dstState := filepath.Join(dir, "dst/state")
	if err := os.MkdirAll(dstState, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RestoreBackupArchive(archive, BackupSources{StateDir: dstState, LearningDir: filepath.Join(dir, "dst/learning")}); err != nil {
		t.Fatal(err)
	}
	if declaredRestore(t, dstState) {
		t.Fatal("a restore without learning state was marked")
	}
	if _, err := os.Stat(filepath.Join(dir, "dst/learning")); !os.IsNotExist(err) {
		t.Fatalf("restore created a learning directory: %v", err)
	}
}
