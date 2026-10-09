package antispam

import (
	"strconv"
	"strings"
)

// ManagedHeader is the first line of every rspamd file CSM owns.
const ManagedHeader = "# csm-managed-version: 1"

// RspamdFiles lists the local.d files CSM owns, in write order.
var RspamdFiles = []string{"actions.conf", "greylist.conf", "rbl.conf", "emails.conf", "fuzzy_check.conf", "asn.conf"}

// disabledModule turns one rspamd module off. Core makes no third-party
// lookups: rbl, emails and fuzzy_check query outside lists, asn sends sender
// IPs to rspamd.com, and greylist would defer mail.
const disabledModule = ManagedHeader + "\nenabled = false;\n"

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
