package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// logrotate skips a config that group or others can write, so CSM's logs
// would never rotate.

func TestPackagedLogrotateConfigHasMode0644(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "build", "nfpm.yaml"))
	if err != nil {
		t.Fatalf("read nfpm package manifest: %v", err)
	}
	var manifest struct {
		Contents []struct {
			Dst      string `yaml:"dst"`
			FileInfo struct {
				Mode string `yaml:"mode"`
			} `yaml:"file_info"`
		} `yaml:"contents"`
	}
	if err := yaml.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("parse nfpm package manifest: %v", err)
	}
	for _, entry := range manifest.Contents {
		if entry.Dst == "/etc/logrotate.d/csm" {
			if entry.FileInfo.Mode != "0644" {
				t.Fatalf("/etc/logrotate.d/csm mode = %q, want 0644 (otherwise it takes the build checkout's mode)", entry.FileInfo.Mode)
			}
			return
		}
	}
	t.Fatal("package manifest must install /etc/logrotate.d/csm")
}

func TestWriteLogrotateResetsAGroupWritableConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0664); err != nil {
		t.Fatal(err)
	}
	if err := writeLogrotate(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0644 {
		t.Fatalf("mode = %o, want 644", mode)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != logrotateConfig() {
		t.Fatal("logrotate config content was not written")
	}
}
