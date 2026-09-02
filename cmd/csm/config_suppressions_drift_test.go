package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// The installer's embedded template, the packaged csm.yaml.default and the
// code defaults must agree. The template shipped a private token label in
// known_api_tokens and no suppress_webmail_alerts line at all, so a fresh
// install and a packaged install behaved differently.
func TestSuppressionDefaultsAgreeAcrossReferences(t *testing.T) {
	rendered := filepath.Join(t.TempDir(), "csm.yaml")
	if err := deployDefaultConfig(rendered); err != nil {
		t.Fatalf("deployDefaultConfig: %v", err)
	}
	fromTemplate := loadSuppressions(t, rendered)
	fromPackage := loadSuppressions(t, filepath.Join("..", "..", "build", "packaging", "csm.yaml.default"))
	fromCode, err := config.LoadBytes([]byte("hostname: test\n"))
	if err != nil {
		t.Fatal(err)
	}

	if len(fromTemplate.KnownAPITokens) != 0 {
		t.Errorf("installer template ships known_api_tokens %v; the packaged default ships none", fromTemplate.KnownAPITokens)
	}
	if len(fromPackage.KnownAPITokens) != 0 {
		t.Errorf("packaged default ships known_api_tokens %v", fromPackage.KnownAPITokens)
	}
	if fromTemplate.SuppressWebmail != fromPackage.SuppressWebmail || fromPackage.SuppressWebmail != fromCode.Suppressions.SuppressWebmail {
		t.Errorf("suppress_webmail_alerts drift: template=%v package=%v code=%v",
			fromTemplate.SuppressWebmail, fromPackage.SuppressWebmail, fromCode.Suppressions.SuppressWebmail)
	}
}

func loadSuppressions(t *testing.T, path string) struct {
	KnownAPITokens  []string
	SuppressWebmail bool
} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes(%s): %v", path, err)
	}
	return struct {
		KnownAPITokens  []string
		SuppressWebmail bool
	}{cfg.Suppressions.KnownAPITokens, cfg.Suppressions.SuppressWebmail}
}
