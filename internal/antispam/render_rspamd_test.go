package antispam

import (
	"regexp"
	"strings"
	"testing"
	"unicode"
)

func TestRenderRspamdMatchesVerifiedFiles(t *testing.T) {
	files, err := RenderRspamd(defaults(false))
	if err != nil {
		t.Fatal(err)
	}
	letters := `[\x{1100}-\x{11FF}\x{3005}\x{303B}\x{3041}-\x{3096}\x{309D}-\x{309F}` +
		`\x{30A1}-\x{30FA}\x{30FC}-\x{30FF}\x{3131}-\x{318E}\x{31F0}-\x{31FF}` +
		`\x{3400}-\x{4DBF}\x{4E00}-\x{9FFF}\x{A960}-\x{A97C}\x{AC00}-\x{D7A3}` +
		`\x{D7B0}-\x{D7C6}\x{D7CB}-\x{D7FB}\x{F900}-\x{FA6D}\x{FA70}-\x{FAD9}` +
		`\x{FF66}-\x{FF9D}\x{FFA0}-\x{FFBE}\x{FFC2}-\x{FFC7}\x{FFCA}-\x{FFCF}\x{FFD2}-\x{FFD7}\x{FFDA}-\x{FFDC}` +
		`\x{16FE3}\x{16FF2}-\x{16FF3}\x{1AFF0}-\x{1AFF3}\x{1AFF5}-\x{1AFFB}\x{1AFFD}-\x{1AFFE}` +
		`\x{1B000}-\x{1B122}\x{1B132}\x{1B150}-\x{1B152}\x{1B155}\x{1B164}-\x{1B167}` +
		`\x{20000}-\x{2A6DF}\x{2A700}-\x{2B81D}\x{2B820}-\x{2CEAD}\x{2CEB0}-\x{2EBE0}` +
		`\x{2EBF0}-\x{2EE5D}\x{2F800}-\x{2FA1D}\x{30000}-\x{3134A}\x{31350}-\x{33479}]`
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
			"  re = 'Subject=/" + letters + `[\x{0300}-\x{036F}\x{302A}-\x{302F}\x{3099}-\x{309A}\x{FE00}-\x{FE0F}\x{FE20}-\x{FE2F}\x{E0100}-\x{E01EF}]*` +
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

var invisibleCJKSubjects = map[string]bool{
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

	"\u3005\u200b!":             true,  // Han iteration mark
	"\u303b\u200b!":             true,  // vertical Han iteration mark
	"\U00016ff2\u200b!":         true,  // Han reading mark
	"\U00033479\u200b!":         true,  // last assigned Han letter
	"\U0003347a\u200b!":         false, // beyond assigned Han letters
	"\U00016fe3\u200b!":         true,  // old Chinese iteration mark
	"\U0001b000\u200b!":         true,  // supplementary katakana
	"\u200b\U0001b001":          true,  // supplementary hiragana
	"\U0001aff0\u200b!":         true,  // kana extended B
	"\u304b\u0301\u200b!":       true,  // inherited combining accent
	"\u4e00\u302a\u200b!":       true,  // ideographic tone mark
	"\uac00\u302e\u200b!":       true,  // Hangul tone mark after a letter
	"\u4e00\u0301\u3099\u200b!": true,  // multiple combining marks
	"\u4e00\U0001d165\u200b!":   false, // musical notation mark, never in CJK text
	"\ufa6e\u200b":              false, // compatibility ideograph gap
	"\ufada\u200b":              false, // beyond compatibility ideographs
	"\U0002a6e0\u200b":          false, // gap between Han extensions
	"\U0002fa1e\u200b":          false, // beyond compatibility supplement
	"\U0002ffff\u200b":          false, // noncharacter
	"\u200b\ud7c7":              false, // jamo extension gap
	"\u200b\uffbf":              false, // half-width jamo gap
	"\u200b\u0301":              false, // standalone combining accent
	"\u302a\u200b":              false, // standalone ideographic tone mark
	"\u302e\u200b":              false, // standalone Hangul tone mark
	"\U0001d165\u200b":          false, // standalone supplementary mark
	"a\u0301\u200b!":            false, // Latin base with an accent
}

// The rendered pattern must compile in RE2 as well as PCRE, so this table
// runs everywhere; the integration test replays it through rspamd.
func TestInvisibleCJKMatchesHiddenCharactersOnly(t *testing.T) {
	for _, unsupported := range []string{`\p{`, `\P{`, `(?=`, `(?!`, `(?<=`, `(?<!`} {
		if strings.Contains(invisibleCJK, unsupported) {
			t.Fatalf("pattern contains engine-dependent syntax %q", unsupported)
		}
	}
	re := regexp.MustCompile(invisibleCJK)
	for subject, want := range invisibleCJKSubjects {
		if got := re.MatchString(subject); got != want {
			t.Errorf("match(%+q) = %v, want %v", subject, got, want)
		}
	}
}

func TestInvisibleCJKUnicodeClasses(t *testing.T) {
	letters := regexp.MustCompile(`^[` + cjkLetters + `]$`)
	marks := regexp.MustCompile(`^[` + letterMarks + `]$`)
	for r := rune(0); r <= unicode.MaxRune; r++ {
		wantLetter := unicode.IsLetter(r) &&
			(unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul) || r == '\u30fc' || r == '\uff70')
		if got := letters.MatchString(string(r)); got != wantLetter {
			t.Fatalf("letter %U = %v, want %v", r, got, wantLetter)
		}
		if marks.MatchString(string(r)) && !unicode.IsMark(r) {
			t.Fatalf("%U is in letterMarks but is not a mark", r)
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
