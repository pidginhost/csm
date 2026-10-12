package txn

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplaceStagedFileRefusesEditsDuringPreparation(t *testing.T) {
	for _, existed := range []bool{false, true} {
		t.Run(fmt.Sprint(existed), func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "hook")
			want := fileState{}
			if existed {
				writeTest(t, p, "old", 0o600)
				want = fileState{exists: true, content: "old"}
			}
			tmp := stagedTestFile(t, p)
			writeTest(t, p, "external edit", 0o640)
			if err := replaceStagedFile(p, want, tmp, 0); !errors.Is(err, errConflict) {
				t.Fatalf("staged replacement = %v; want conflict", err)
			}
			if st, err := readFile(p); err != nil || st.content != "external edit" || st.perm != 0o640 {
				t.Fatalf("external edit changed: %+v, %v", st, err)
			}
		})
	}
}

func TestReplaceStagedFileKeepsLatestMetadata(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hook")
	writeTest(t, p, "old", 0o644)
	tmp := stagedTestFile(t, p)
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceStagedFile(p, fileState{exists: true, content: "old"}, tmp, 0); err != nil {
		t.Fatal(err)
	}
	if st, err := readFile(p); err != nil || st.content != "new" || st.perm != 0o600 {
		t.Fatalf("latest metadata lost: %+v, %v", st, err)
	}
}

func TestPublishFileDoesNotOverwriteNewDestination(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hook")
	tmp := stagedTestFile(t, p)
	writeTest(t, p, "external creation", 0o600)
	if err := publishFile(p, tmp, 0o644, -1, -1, false); !errors.Is(err, errConflict) {
		t.Fatalf("publish to new destination = %v; want conflict", err)
	}
	if st, err := readFile(p); err != nil || st.content != "external creation" {
		t.Fatalf("external creation overwritten: %+v, %v", st, err)
	}
}

func stagedTestFile(t *testing.T, p string) *os.File {
	t.Helper()
	tmp, err := os.CreateTemp(filepath.Dir(p), ".test-*.csmtmp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	})
	if _, err := tmp.WriteString("new"); err != nil {
		t.Fatal(err)
	}
	return tmp
}

func TestPrivateDirRejectsForeignOwner(t *testing.T) {
	d := realTempDir(t)
	if err := privateDirOwned(d, os.Geteuid()+1); err == nil || !strings.Contains(err.Error(), "not owned by the worker") {
		t.Fatalf("foreign owner = %v; want an ownership error", err)
	}
}
