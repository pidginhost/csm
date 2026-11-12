package signatures

import (
	"strings"
	"testing"
)

// Spam keywords count only as whole words near the text they stuff, so a
// single-line translation file or an ordinary word containing one stays quiet.
func TestSpamKeywordRulesMatchWholeWords(t *testing.T) {
	scanner := loadRepoScanner(t)
	kana := strings.Repeat("あ", 10)
	for _, tc := range []struct {
		name, rule, ext, sample string
		want                    bool
	}{
		{"translation file word containing cialis", "spam_japanese_seo", ".php",
			"<?php\nreturn ['messages'=>['Hire'=>'" + kana + "','Hand-picked specialists for any project'=>'" + kana + "']];", false},
		{"keyword far from the Japanese text", "spam_japanese_seo", ".html",
			"<p>" + kana + "</p>" + strings.Repeat("<span>plain text</span>", 12) + "<p>casino</p>", false},
		{"keyword prefix of a longer word", "spam_japanese_seo", ".html",
			"<p>" + kana + " casinova slotting</p>", false},
		{"stuffed kana beside a keyword", "spam_japanese_seo", ".html",
			"<p>" + kana + " viagra online</p>", true},
		{"plural slot keyword", "spam_japanese_seo", ".html",
			"<p>" + kana + ` <a href="https://spam.example.test/">free slots</a></p>`, true},
		{"post title containing specialists", "spam_wp_post_injector", ".php",
			`<?php wp_insert_post(array('post_title' => 'Hand-picked specialists', 'post_status' => 'draft'));`, false},
		{"post with a pharma keyword", "spam_wp_post_injector", ".php",
			`<?php wp_insert_post(array('post_title' => 'cheap cialis online', 'post_status' => 'publish'));`, true},
		{"post with plural casino keyword", "spam_wp_post_injector", ".php",
			`<?php wp_insert_post(array('post_content' => 'best casinos 2026'));`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasRule(scanner.ScanContent([]byte(tc.sample), tc.ext), tc.rule); got != tc.want {
				t.Errorf("%s match = %t, want %t", tc.rule, got, tc.want)
			}
		})
	}
}
