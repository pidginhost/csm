package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPHPPhishingRequestAliases(t *testing.T) {
	for _, alias := range []string{
		`$_POST`, `${'_POST'}`, `${"_POST"}`, `$GLOBALS['_POST']`, `$GLOBALS["_POST"]`,
		`${/* input */'_POST'}`, `$_REQUEST`, `${'_REQUEST'}`, `$GLOBALS['_REQUEST']`,
	} {
		for _, page := range []string{
			`<img src="dropbox-logo.png" alt="Dropbox"><form><input type="password" name="password"></form>`,
			`<h1>Dropbox</h1>`,
		} {
			t.Run(alias+"/"+page, func(t *testing.T) {
				content := "<?php\n$password = " + alias + "['password'];\nfile_put_contents('results.txt', $password);\n?>" + page
				if !mayBePHPPhishing([]byte(content)) {
					t.Error("prefilter rejected executable request input")
				}
				path := filepath.Join(t.TempDir(), "shared-document.php")
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
				result := analyzePHPForPhishing(context.Background(), path)
				if result == nil || result.brand != "Dropbox" {
					t.Fatalf("password capture with a visible brand not detected: %+v", result)
				}
				if !strings.Contains(strings.Join(result.indicators, "\n"), "PHP writes credential data to file") {
					t.Fatalf("aliased password did not reach the exfiltration check: %+v", result)
				}
			})
		}
	}
}

func TestPHPPhishingAliasExamplesDoNotEstablishCapture(t *testing.T) {
	for _, example := range []string{
		`'${"_POST"}["password"]'`,
		`'$GLOBALS["_POST"]["password"]'`,
		`"\${'_POST'}['password']"`,
		"<<<'TEXT'\n${'_POST'}['password']\nTEXT",
	} {
		content := "<?php $example = " + example + "; file_put_contents('results.txt', $example); ?>" +
			`<h1>Dropbox backup</h1><form><input type="password" name="password"></form>`
		if result := analyzePHPPhishingContent(content); result != nil {
			t.Errorf("literal request example established password capture: %+v", result)
		}
	}
}
