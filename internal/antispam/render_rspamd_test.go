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
	letters := "[\\x{3041}-\\x{3096}\\x{309D}-\\x{309F}\\x{30A1}-\\x{30FA}\\x{30FC}-\\x{30FF}\\x{31F0}-\\x{31FF}\\x{FF66}-\\x{FF9D}\\x{3400}-\\x{4DBF}\\x{4E00}-\\x{9FFF}\\x{F900}-\\x{FAFF}\\x{20000}-\\x{323AF}\\x{1100}-\\x{11FF}\\x{3131}-\\x{318E}\\x{A960}-\\x{A97C}\\x{AC00}-\\x{D7A3}\\x{D7B0}-\\x{D7FB}\\x{FFA0}-\\x{FFDC}]"
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
			"  re = 'Subject=/" + letters + "[\\x{3099}\\x{309A}\\x{FE00}-\\x{FE0F}\\x{E0100}-\\x{E01EF}]*" +
			"[\\x{200B}-\\x{200D}\\x{2060}\\x{FEFF}]|[\\x{200B}-\\x{200D}\\x{2060}\\x{FEFF}]" + letters + "/u';\n" +
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

// The rendered pattern must compile in RE2 as well as PCRE, so this table
// runs everywhere; the integration test replays it through rspamd.
func TestInvisibleCJKMatchesHiddenCharactersOnly(t *testing.T) {
	re := regexp.MustCompile(invisibleCJK)
	for subject, want := range map[string]bool{
		"\u304a\u77e5\u3089\u200b\u305b":                   true,
		"\u200c\u91cd\u8981\u306a\u304a\u77e5\u3089\u305b": true,
		"\u4ee4\u548c\ufeff7":                              true,
		"\uc548\ub0b4\u2060\ub4dc\ub9bd\ub2c8\ub2e4":       true,
		"\u30ab\u30bf\u30ab\u30ca\u200d!":                  true,
		"\u304b\u3099\u200b!":                              true, // decomposed kana
		"\u6f22\U000e0100\u200b!":                          true, // Han variation selector
		"\uff76\u200b\uff80\uff76\uff85":                   true, // half-width kana
		"\u200b\uff70":                                     true, // half-width prolonged sound mark
		"\u30fc\u200b":                                     true, // prolonged sound mark
		"\u3400\u200b\u3401":                               true, // Han extension A
		"\U00020000\u200b\U00020001":                       true, // supplementary Han
		"\u1100\u200b\u1161":                               true, // decomposed Hangul
		"\u3131\u2060\u314f":                               true, // compatibility jamo
		"\u304a\u77e5\u3089\u305b\u3067\u3059":             false,
		"Retur\u200b produs":                               false,
		"\U0001f468\u200d\U0001f469 family":                false,
		"\u3010\u200b\u3011":                               false,
		"Notice\u30fb\u200bupdate":                         false, // middle dot
		"\u200b\u30a0":                                     false, // double hyphen
		"\u309b\u200b":                                     false, // spacing dakuten
		"\u200b\u3099":                                     false, // combining dakuten
		"\u2f00\u200b":                                     false, // Han radical symbol, not a letter
		"\u200b\u302e":                                     false, // Hangul tone mark
		"\u200b\u3040":                                     false, // unassigned code point
		"\ud7a4\u200b":                                     false, // beyond Hangul syllables
		"Weekly digest":                                    false,
		"":                                                 false,
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
