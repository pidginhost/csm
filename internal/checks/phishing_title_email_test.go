package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A blog author archive is titled after the author, and an author who signs up
// with a webmail address gets that address (or its slug) in the title. A cached
// copy of such a page also carries the comment form and a newsletter form that
// posts to the mailing-list provider.
const authorArchiveTemplate = `<!DOCTYPE html><html><head><title>%TITLE%</title></head><body>
<h1>Posts by the author</h1>
<form action="https://lists.example.net/subscribe" method="post"><input type="email" name="email"><button>Subscribe</button></form>
<form action="/wp-comments-post.php" method="post"><input type="email" name="email"><textarea name="comment"></textarea></form>
</body></html>`

func writeHTMLForPhishingTest(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAnalyzeHTMLForPhishingWebmailAddressInTitleIsNotImpersonation(t *testing.T) {
	for name, title := range map[string]string{
		"address":       "Posts by jane.doe@gmail.com - Example Blog",
		"percent":       "Posts by jane%@gmail.com - Example Blog",
		"login address": "Login tips by jane.doe@gmail.com - Example Blog",
		"slug":          "Author: janedoegmail-com | Example Blog",
		"prefix":        "Gmailers weekly digest - Example Blog",
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(authorArchiveTemplate, "%TITLE%", title, 1)
			if res := analyzeHTMLForPhishing(context.Background(), writeHTMLForPhishingTest(t, "index.html", body)); res != nil {
				t.Errorf("author archive flagged as %s phishing: %v", res.brand, res.indicators)
			}
		})
	}
}

func TestAnalyzeHTMLForPhishingBrandWordTitleStillScores(t *testing.T) {
	body := `<html><head><title>Gmail - Sign in</title></head><body>
<form action="https://collector.example.net/p.php" method="post">
<input type="email" name="email"><input type="password" name="password"></form></body></html>`
	res := analyzeHTMLForPhishing(context.Background(), writeHTMLForPhishingTest(t, "login.html", body))
	if res == nil || res.brand != "Google" {
		t.Fatalf("brand-titled credential page not flagged as Google phishing: %+v", res)
	}
}

func TestPhishingTitleBrandDecorationStillScores(t *testing.T) {
	for _, title := range []string{"Gmail2", "2Gmail", "@Gmail", "GmailLogin", "MyGmail - Sign in"} {
		t.Run(title, func(t *testing.T) {
			body := `<html><head><title>` + title + `</title></head><body>
<form action="https://collector.example.net/p.php" method="post">
<input type="email" name="email"><input type="password" name="password"></form></body></html>`
			for _, password := range []bool{true, false} {
				page := body
				if !password {
					page = strings.Replace(page, `<input type="password" name="password">`, "", 1)
				}
				for _, ext := range []string{".html", ".php"} {
					path := writeHTMLForPhishingTest(t, "login"+ext, page)
					var res *phishingResult
					if ext == ".html" {
						res = analyzeHTMLForPhishing(context.Background(), path)
					} else {
						path = writeHTMLForPhishingTest(t, "login.php", `<?php $p = $_POST['email']; ?>`+page)
						res = analyzePHPForPhishing(context.Background(), path)
					}
					if res == nil || res.brand != "Google" {
						t.Errorf("%s password=%t: decorated brand title fell below the phishing floor: %+v", ext, password, res)
					}
				}
			}
		})
	}
}

func TestAnalyzePHPForPhishingWebmailAddressInTitleIsNotImpersonation(t *testing.T) {
	body := `<?php if ($_SERVER['REQUEST_METHOD'] === 'POST') { $p = $_POST['password']; } ?>` +
		strings.Replace(authorArchiveTemplate, "%TITLE%", "Posts by jane.doe@gmail.com - Example Blog", 1)
	if res := analyzePHPForPhishing(context.Background(), writeHTMLForPhishingTest(t, "author.php", body)); res != nil {
		t.Errorf("author template flagged as %s phishing: %v", res.brand, res.indicators)
	}
}
