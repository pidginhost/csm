package checks

import (
	"os"
	"testing"
)

func TestFakeDirEntryMethods(t *testing.T) {
	// Create a real file to get a FileInfo
	dir := t.TempDir()
	path := dir + "/test.txt"
	_ = os.WriteFile(path, []byte("hello"), 0644)
	fi, _ := os.Stat(path)

	fde := fakeDirEntry{fi: fi}
	if fde.Name() != "test.txt" {
		t.Errorf("Name = %q", fde.Name())
	}
	if fde.IsDir() {
		t.Error("file should not be dir")
	}
	if fde.Type().IsDir() {
		t.Error("type should not be dir")
	}
	info, err := fde.Info()
	if err != nil || info == nil {
		t.Errorf("Info() = %v, %v", info, err)
	}
}
