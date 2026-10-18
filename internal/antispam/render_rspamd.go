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
const (
	cjkLetters     = `\x{3040}-\x{30FF}\x{4E00}-\x{9FFF}\x{AC00}-\x{D7AF}`
	invisibleChars = `\x{200B}-\x{200D}\x{2060}\x{FEFF}`
	invisibleCJK   = `[` + cjkLetters + `][` + invisibleChars + `]|[` + invisibleChars + `][` + cjkLetters + `]`
)

// subjectRules scores the decoded Subject. On its own the weight lifts an
// authenticated message over the default tag score, not to the default
// reject score.
const subjectRules = ManagedHeader + "\nCSM_INVISIBLE_CJK_SUBJECT {\n" +
	"  re = 'Subject=/" + invisibleCJK + "/u';\n" +
	"  score = 8.0;\n" +
	"  description = \"Invisible character inside CJK text in Subject\";\n}\n"

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
