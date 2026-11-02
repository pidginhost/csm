package hostfacts

import (
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/antispam"
)

func TestGroupFilesReadsOtherOperatorGroups(t *testing.T) {
	dir := t.TempDir()
	mkdir(t, filepath.Join(dir, "local.d"))
	mkdir(t, filepath.Join(dir, "override.d"))
	const content = "symbols { DMARC_POLICY_REJECT { weight = 5; } }\n"
	write(t, filepath.Join(dir, "local.d", "mime_group.conf"), content)
	write(t, filepath.Join(dir, "override.d", "policies_group.conf"), "symbols {}\n")
	write(t, filepath.Join(dir, "local.d", "groups.conf"), antispam.ManagedHeader+"\n")
	files := groupFiles(filepath.Join(dir, "local.d"))
	if got, ok := files["mime"]; !ok || got.Err != nil || got.Content != content {
		t.Fatalf("operator group was not collected: %+v, present %v", got, ok)
	}
	if got := files["policies"]; got.Err != nil || got.Content != "" {
		t.Fatalf("override group leaked into local facts: %+v", got)
	}
	if _, ok := files["groups"]; ok {
		t.Fatal("CSM's own weights were collected as operator definitions")
	}
}

func TestGroupFilesCannotListDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "local.d")
	write(t, file, "not a directory")
	files := groupFiles(file)
	for _, group := range antispam.ScoreGroups() {
		if got := files[group]; got.Err == nil || got.Content != "" {
			t.Fatalf("unreadable directory claimed known definitions for %s: %+v", group, got)
		}
	}
}
