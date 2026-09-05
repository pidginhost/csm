package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestCleanHtaccessUsesConfiguredAccountRoot(t *testing.T) {
	root := mustEvalSymlinks(t, t.TempDir())
	contentRoot := filepath.Join(root, "alice", "public")
	if err := os.MkdirAll(contentRoot, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(contentRoot, ".htaccess")
	if err := os.WriteFile(path, []byte("# keep\nAddHandler cgi-script .alfa\n"), 0640); err != nil {
		t.Fatal(err)
	}
	previous := config.Active()
	config.SetActive(&config.Config{AccountRoots: []string{filepath.Join(root, "*", "public")}})
	t.Cleanup(func() { config.SetActive(previous) })
	withHtaccessBackupRoot(t)
	result := CleanHtaccessFile(path)
	if !result.Success {
		t.Fatal(result)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "# keep\n" {
		t.Fatalf("cleaned content=%q error=%v", data, err)
	}
	sibling := filepath.Join(root, "alice", ".htaccess")
	malicious := []byte("AddHandler cgi-script .alfa\n")
	if writeErr := os.WriteFile(sibling, malicious, 0600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if result := CleanHtaccessFile(sibling); result.Success {
		t.Fatal("cleaned an unconfigured sibling")
	}
	unchanged, readErr := os.ReadFile(sibling)
	if readErr != nil || string(unchanged) != string(malicious) {
		t.Fatalf("unconfigured sibling changed: %q %v", unchanged, readErr)
	}
}
