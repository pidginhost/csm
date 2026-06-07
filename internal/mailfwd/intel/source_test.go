package intel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTailLinesKeepsLastLineWhenFileEndsWithNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exim_mainlog")
	if err := os.WriteFile(path, []byte("old\nnew\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got := tailLines(path, 1024, 1)
	if len(got) != 1 || got[0] != "new" {
		t.Fatalf("tailLines = %#v, want [new]", got)
	}
}

func TestTailLinesDropsPartialFirstLineAfterByteWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exim_mainlog")
	if err := os.WriteFile(path, []byte("partial\nkeep\nlast\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got := tailLines(path, 10, 10)
	if len(got) != 1 || got[0] != "last" {
		t.Fatalf("tailLines = %#v, want [last]", got)
	}
}
