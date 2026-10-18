package antispam

import (
	"regexp"
	"testing"
)

func TestRenderRspamdMatchesVerifiedFiles(t *testing.T) {
	files, err := RenderRspamd(defaults(false))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"actions.conf":     "# csm-managed-version: 1\nreject = 15;\nadd_header = 6;\ngreylist = null;\nrewrite_subject = null;\n",
		"greylist.conf":    "# csm-managed-version: 1\nenabled = false;\n",
		"rbl.conf":         "# csm-managed-version: 1\nenabled = false;\n",
		"emails.conf":      "# csm-managed-version: 1\nenabled = false;\n",
		"fuzzy_check.conf": "# csm-managed-version: 1\nenabled = false;\n",
		"asn.conf":         "# csm-managed-version: 1\nenabled = false;\n",
		"phishing.conf": "# csm-managed-version: 1\nphishtank_enabled = false;\nexceptions {\n" +
			"  REDIRECTOR_FALSE = \"/etc/rspamd/maps.d/redirectors.inc\";\n" +
			"  PHISHED_WHITELISTED = \"glob;/etc/rspamd/local.d/maps.d/phishing_whitelist.inc\";\n}\n",
		"regexp.conf": "# csm-managed-version: 1\nCSM_INVISIBLE_CJK_SUBJECT {\n" +
			"  re = 'Subject=/[\\x{3040}-\\x{30FF}\\x{4E00}-\\x{9FFF}\\x{AC00}-\\x{D7AF}][\\x{200B}-\\x{200D}\\x{2060}\\x{FEFF}]|" +
			"[\\x{200B}-\\x{200D}\\x{2060}\\x{FEFF}][\\x{3040}-\\x{30FF}\\x{4E00}-\\x{9FFF}\\x{AC00}-\\x{D7AF}]/u';\n" +
			"  score = 8.0;\n  description = \"Invisible character inside CJK text in Subject\";\n}\n",
	}
	if len(files) != len(want) {
		t.Fatalf("rendered %d files, want %d: %v", len(files), len(want), files)
	}
	for name, content := range want {
		if files[name] != content {
			t.Errorf("%s = %q, want %q", name, files[name], content)
		}
	}
	for _, name := range RspamdFiles {
		if _, ok := files[name]; !ok {
			t.Errorf("RspamdFiles lists %s but it was not rendered", name)
		}
	}
}

func TestInvisibleCJKMatchesHiddenCharactersOnly(t *testing.T) {
	re := regexp.MustCompile(invisibleCJK)
	for subject, want := range map[string]bool{
		"\u304a\u77e5\u3089\u200b\u305b":                   true,  // zero-width space between kana
		"\u200c\u91cd\u8981\u306a\u304a\u77e5\u3089\u305b": true,  // before a kanji
		"\u4ee4\u548c\ufeff7":                              true,  // BOM after a kanji
		"\uc548\ub0b4\u2060\ub4dc\ub9bd\ub2c8\ub2e4":       true,  // word joiner in Hangul
		"\u30ab\u30bf\u30ab\u30ca\u200d!":                  true,  // joiner after katakana
		"\u304a\u77e5\u3089\u305b\u3067\u3059":             false, // CJK without invisible characters
		"Retur\u200b produs":                               false, // zero-width space in Latin text
		"\U0001f468\u200d\U0001f469 family":                false, // emoji joiner
		"\u3010\u200b\u3011":                               false, // CJK punctuation is not text
		"Weekly digest":                                    false,
	} {
		if got := re.MatchString(subject); got != want {
			t.Errorf("match(%+q) = %v, want %v", subject, got, want)
		}
	}
}

func TestRenderRspamdThresholdsFollowSettings(t *testing.T) {
	s := defaults(true)
	s.RejectScore, s.TagScore = 20, 8
	files, err := RenderRspamd(s)
	if err != nil {
		t.Fatal(err)
	}
	want := "# csm-managed-version: 1\nreject = 20;\nadd_header = 8;\ngreylist = null;\nrewrite_subject = null;\n"
	if files["actions.conf"] != want {
		t.Errorf("actions.conf = %q, want %q", files["actions.conf"], want)
	}
}

func TestIsManaged(t *testing.T) {
	for content, want := range map[string]bool{
		"# csm-managed-version: 1\nenabled = false;\n": true,
		"# csm-managed-version: 1":                     true,
		"# csm-managed-version: 2\nenabled = false;\n": false,
		"enabled = false;\n# csm-managed-version: 1\n": false,
		" # csm-managed-version: 1\n":                  false,
		"":                                             false,
	} {
		if got := IsManaged(content); got != want {
			t.Errorf("IsManaged(%q) = %v, want %v", content, got, want)
		}
	}
}
