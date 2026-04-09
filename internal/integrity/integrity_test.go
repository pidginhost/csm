package integrity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashConfigStable_ReturnsScannerError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	oversizedLine := strings.Repeat("a", 70*1024)
	data := "hostname: test.example\n" + oversizedLine + "\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := HashConfigStable(path); err == nil {
		t.Fatal("HashConfigStable() = nil error, want scanner failure")
	}
}
