package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// The content check already cleared a translation cache in
// wp-content/languages; a word in its name must not flag it again, while a
// real shell under a similar name is still reported.
func TestContentClearedLanguageFileIgnoresNameWords(t *testing.T) {
	lang := filepath.Join(t.TempDir(), "public_html", "wp-content", "languages", "plugins")
	if err := os.MkdirAll(lang, 0o755); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(lang, "connect-polylang-elementor-ro_RO.l10n.php")
	shell := filepath.Join(lang, "connect-ro_RO.l10n.php")
	if err := os.WriteFile(cache, []byte("<?php\nreturn ['messages'=>['Save'=>'Salveaza']];"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shell, []byte(evalWebshell), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := checkFileIndexAnalyzeNewFiles(context.Background(), &config.Config{}, []string{cache, shell})
	flagged := false
	for _, f := range findings {
		if f.FilePath == cache {
			t.Fatalf("content-cleared translation cache flagged by its name: %+v", f)
		}
		if f.FilePath == shell && f.Severity >= alert.High {
			flagged = true
		}
	}
	if !flagged {
		t.Fatalf("shell in wp-content/languages not flagged: %+v", findings)
	}
}
