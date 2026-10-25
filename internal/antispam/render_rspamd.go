package antispam

import (
	"strconv"
	"strings"
)

// ManagedHeader is the first line of every rspamd file CSM owns.
const ManagedHeader = "# csm-managed-version: 1"

// RspamdFiles lists the local.d files CSM owns, in write order.
var RspamdFiles = []string{"actions.conf", "greylist.conf", "rbl.conf", "emails.conf", "fuzzy_check.conf", "asn.conf", "phishing.conf", "regexp.conf"}

// disabledModule turns one rspamd module off. Core makes no third-party
// lookups: rbl, emails and fuzzy_check query outside lists, asn sends sender
// IPs to rspamd.com, and greylist would defer mail. rbl stays off unless the
// operator enables a DNS feed.
const disabledModule = ManagedHeader + "\nenabled = false;\n"

// invisibleCJK matches an invisible character next to a Chinese, Japanese
// or Korean letter. Spam puts them inside subject words to split them for
// filters; legitimate subjects use them beside Latin text or inside emoji.
// Explicit Unicode 17.0 letter ranges keep RE2, PCRE and Hyperscan independent
// of the engine's Unicode version. Gaps must stay excluded: they contain
// unassigned code points, not letters. Combining accents, tone marks, kana
// voicing marks and variation selectors may follow a letter. The lists are
// static so the rendered file never changes with the Go toolchain.
const (
	cjkLetters = `\x{1100}-\x{11FF}\x{3005}\x{303B}\x{3041}-\x{3096}\x{309D}-\x{309F}` +
		`\x{30A1}-\x{30FA}\x{30FC}-\x{30FF}\x{3131}-\x{318E}\x{31F0}-\x{31FF}` +
		`\x{3400}-\x{4DBF}\x{4E00}-\x{9FFF}\x{A960}-\x{A97C}\x{AC00}-\x{D7A3}` +
		`\x{D7B0}-\x{D7C6}\x{D7CB}-\x{D7FB}\x{F900}-\x{FA6D}\x{FA70}-\x{FAD9}` +
		`\x{FF66}-\x{FF9D}\x{FFA0}-\x{FFBE}\x{FFC2}-\x{FFC7}\x{FFCA}-\x{FFCF}\x{FFD2}-\x{FFD7}\x{FFDA}-\x{FFDC}` +
		`\x{16FE3}\x{16FF2}-\x{16FF3}\x{1AFF0}-\x{1AFF3}\x{1AFF5}-\x{1AFFB}\x{1AFFD}-\x{1AFFE}` +
		`\x{1B000}-\x{1B122}\x{1B132}\x{1B150}-\x{1B152}\x{1B155}\x{1B164}-\x{1B167}` +
		`\x{20000}-\x{2A6DF}\x{2A700}-\x{2B81D}\x{2B820}-\x{2CEAD}\x{2CEB0}-\x{2EBE0}` +
		`\x{2EBF0}-\x{2EE5D}\x{2F800}-\x{2FA1D}\x{30000}-\x{3134A}\x{31350}-\x{33479}`
	letterMarks    = `\x{0300}-\x{036F}\x{302A}-\x{302F}\x{3099}-\x{309A}\x{FE00}-\x{FE0F}\x{FE20}-\x{FE2F}\x{E0100}-\x{E01EF}`
	invisibleChars = `\x{200B}-\x{200D}\x{2060}\x{FEFF}`
	invisibleCJK   = `[` + cjkLetters + `][` + letterMarks + `]*[` + invisibleChars + `]|[` + invisibleChars + `][` + cjkLetters + `]`
)

// subjectRules scores the decoded Subject. On its own the weight lifts an
// authenticated message over the default tag score, not to the default
// reject score.
const subjectRules = ManagedHeader + "\nCSM_INVISIBLE_CJK_SUBJECT {\n" +
	"  re = 'Subject=/" + invisibleCJK + "/u';\n" +
	"  score = 8.0;\n" +
	"  description = \"Invisible character inside CJK text in Subject\";\n}\n"

// scoreWeights lowers rspamd's HIDDEN_TEXT, which gives up to 5 points for
// hidden text. Newsletters hide their preview line that way, so at the
// default tag score the rule and one minor symbol were enough to tag them.
// URL_VERY_LONG adds its weight once per long link, so a newsletter full of
// tracking links reached the tag score on that rule alone; one_shot counts
// it once per message. A configured symbol loses rspamd's one_shot unless
// the entry repeats it.
const scoreWeights = ManagedHeader + "\ngroup \"html\" {\n  symbols {\n    \"HIDDEN_TEXT\" {\n" +
	"      weight = 2.0;\n      one_shot = true;\n    }\n  }\n}\n" +
	"group \"url\" {\n  symbols {\n    \"URL_VERY_LONG\" {\n" +
	"      weight = 1.5;\n      one_shot = true;\n    }\n  }\n}\n"

// RenderRspamd returns the content of each file in RspamdFiles, keyed by its
// name under /etc/rspamd/local.d.
func RenderRspamd(s Settings) (map[string]string, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	files := make(map[string]string, len(RspamdFiles))
	for _, name := range RspamdFiles {
		files[name] = disabledModule
	}
	// The phishing module keeps its local checks; only its URL lookups in
	// rspamd.com's phishtank zone go off.
	files["phishing.conf"] = ManagedHeader + "\nphishtank_enabled = false;\n"
	if s.Redirects() {
		files["phishing.conf"] += phishingExceptions
	}
	files["regexp.conf"] = subjectRules
	if len(s.DNSFeeds()) > 0 {
		files["rbl.conf"] = ManagedHeader + "\nenabled = true;\n"
	}
	// Learning queries only CSM's loopback worker; the override drops every
	// other fuzzy rule, including rspamd.com's.
	if s.Learning {
		files["fuzzy_check.conf"] = ManagedHeader + "\nenabled = true;\n"
	}
	files["actions.conf"] = ManagedHeader + "\n" +
		"reject = " + strconv.Itoa(s.RejectScore) + ";\n" +
		"add_header = " + strconv.Itoa(s.TagScore) + ";\n" +
		"greylist = null;\n" +
		"rewrite_subject = null;\n"
	return files, nil
}

// IsManaged reports whether content is a file CSM wrote: its first line is
// exactly ManagedHeader. Any other first line belongs to the operator.
func IsManaged(content string) bool {
	first, _, _ := strings.Cut(content, "\n")
	return first == ManagedHeader
}
