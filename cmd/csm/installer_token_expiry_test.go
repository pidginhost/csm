package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestInstallerRecordsTokenIssueTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csm.yaml")
	before := time.Now().UTC().Truncate(time.Second)
	if err := deployDefaultConfig(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal("cannot load generated configuration")
	}
	if len(cfg.WebUI.Tokens) != 1 {
		t.Fatal("installer did not create one credential")
	}
	tok := cfg.WebUI.Tokens[0]
	issued, err := time.Parse(time.RFC3339, tok.IssuedAt)
	if err != nil || issued.Before(before) || issued.After(time.Now()) {
		t.Fatal("installer did not record the credential issue time")
	}
	if !config.WebUITokenCurrent(tok.IssuedAt, tok.ExpiresAt, issued) || config.WebUITokenCurrent(tok.IssuedAt, tok.ExpiresAt, issued.Add(7*24*time.Hour)) {
		t.Fatal("installer credential does not expire within seven days")
	}
}
