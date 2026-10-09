package antispam

import (
	"reflect"
	"strings"
	"testing"
)

// eximBV is `exim -bV` from the cPanel 11.138 scratch host, shortened.
const eximBV = `Exim version 4.100.1 #2 built 21-Sep-2026 17:18:48
Copyright (c) The Exim Maintainers and contributors in ACKNOWLEDGMENTS file, 2007 - 2026

Support for: Content_Scanning Exim_filter Sieve_filter crypteq iconv() IPv6 PAM Perl OpenSSL DKIM PRDR SPF SRS
Lookups (built-in): cdb dbm dnsdb dsearch iplsearch lsearch passwd
Configuration file is /etc/exim.conf
`

func TestParseEximVersion(t *testing.T) {
	v, err := ParseEximVersion(eximBV)
	if err != nil {
		t.Fatal(err)
	}
	if v != (EximVersion{Major: 4, Minor: 100, Patch: 1, ContentScanning: true}) {
		t.Fatalf("got %+v", v)
	}
	if !v.AtLeast(4, 97) {
		t.Error("4.100.1 must count as newer than 4.97 (numeric, not lexical)")
	}
	old, err := ParseEximVersion("Exim version 4.96 #1 built x\nSupport for: iconv() IPv6\n")
	if err != nil {
		t.Fatal(err)
	}
	if old.AtLeast(4, 97) || old.ContentScanning {
		t.Errorf("4.96 without content scanning parsed as %+v", old)
	}
	if _, err := ParseEximVersion("exim: command not found\n"); err == nil {
		t.Error("output without a version line accepted")
	}
}

func TestParseBeResult(t *testing.T) {
	for _, ok := range [][2]string{{"y\n", ""}, {"n\n", ""}} {
		if err := ParseBeResult(ok[0], ok[1]); err != nil {
			t.Errorf("ParseBeResult(%q) = %v", ok[0], err)
		}
	}
	// Exim exits 0 for an undefined list and prints this instead (spike 1a).
	undefined := "Failed: unable to complete match against \"+csm_no_such_list\": NULL\n"
	for _, bad := range [][2]string{
		{undefined, "2026-10-09 08:12:11 unknown named host list \"+csm_no_such_list\"\n"},
		{"y\n", "some warning\n"},
		{"y", ""},
		{"yes\n", ""},
		{"", ""},
	} {
		if err := ParseBeResult(bad[0], bad[1]); err == nil {
			t.Errorf("ParseBeResult(%q, %q) = nil, want error", bad[0], bad[1])
		}
	}
}

func TestParseEximOptionsAndChunking(t *testing.T) {
	got := ParseEximOptions("no_prdr_enable\nchunking_advertise_hosts = 198.51.100.1\nmessage_size_limit = 50M\nsplit_spool_directory\n")
	want := map[string]string{
		"prdr_enable": "false", "chunking_advertise_hosts": "198.51.100.1",
		"message_size_limit": "50M", "split_spool_directory": "true",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for hosts, off := range map[string]bool{"": true, "198.51.100.1": true, " ": true, "*": false, "192.0.2.0/24": false} {
		if ChunkingOff(hosts) != off {
			t.Errorf("ChunkingOff(%q) = %v, want %v", hosts, !off, off)
		}
	}
}

// generatedConf mimics the shape of cPanel's generated exim.conf: a gated
// SpamAssassin block, an ungated spam-score deny of the kind cPanel's
// acl_deny_spam_score_over_int generates, and the CSM blocks.
const generatedConf = `spamd_address = /run/rspamd/csm-normal.sock variant=rspamd tmo=30s
begin acl
acl_smtp_rcpt:
# CSM-ANTISPAM BEGIN
warn
  set acl_m_csm_rcpt =
# CSM-ANTISPAM END
  accept  domains = +relay_domains
acl_smtp_data:
# CSM-ANTISPAM BEGIN
warn
  spam = nobody:true/defer_ok
  set acl_m_csm_score = $spam_score_int
# CSM-ANTISPAM END
  warn
    condition = ${perl{spamd_is_available}}
    spam =  ${acl_m1}/defer_ok
    add_header = X-Spam-Score: $spam_score_int
.ifdef SOMETHING
  warn
      condition = ${perl{spamd_is_available}}
      condition = ${if eq {$spam_score_int}{}{0}{1}}
.endif
deny
    condition = ${if eq {${acl_m0}}{1}{${if >{$spam_score_int}{100}{1}{0}}}{0}}
    message = "The mail server detected your message as spam."
  deny condition = ${if >{${spam_score_int}}{50}}
# CSM-ANTISPAM BEGIN
deny
  condition = ${if and{{eq{$acl_m_csm_policy}{on}}{>={$acl_m_csm_score}{150}}}}
# CSM-ANTISPAM END
  accept
begin routers
localuser_spam:
    condition = ${if match{$h_x-spam-status:}{\N^Yes\N}{true}{false}}
`

func TestUngatedSpamUses(t *testing.T) {
	got := UngatedSpamUses(generatedConf)
	want := []int{24, 27}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UngatedSpamUses = %v, want %v", got, want)
	}
	clean := strings.Replace(generatedConf, "deny\n    condition = ${if eq {${acl_m0}}", "deny\n    condition = ${perl{spamd_is_available}}\n    condition = ${if eq {${acl_m0}}", 1)
	clean = strings.Replace(clean, "  deny condition = ${if >{${spam_score_int}}{50}}\n", "", 1)
	if got := UngatedSpamUses(clean); len(got) != 0 {
		t.Errorf("gated config flagged at %v", got)
	}
}

func TestHasCutthroughAndForeignSpamdAddress(t *testing.T) {
	if HasCutthrough(generatedConf) {
		t.Error("no cutthrough in fixture")
	}
	if !HasCutthrough("acl_smtp_rcpt:\n  accept control = cutthrough_delivery\n") {
		t.Error("cutthrough control not found")
	}
	if HasCutthrough("# control = cutthrough_delivery\n") {
		t.Error("comment counted as cutthrough")
	}
	local := "@CONFIG@\n# CSM-ANTISPAM BEGIN\nspamd_address = /run/rspamd/csm-normal.sock variant=rspamd tmo=30s\n# CSM-ANTISPAM END\n\n@DIRECTOREND@\n"
	if ForeignSpamdAddress(local) {
		t.Error("CSM's own spamd_address counted as foreign")
	}
	if !ForeignSpamdAddress(strings.Replace(local, "@DIRECTOREND@", "spamd_address = 127.0.0.1 783\n@DIRECTOREND@", 1)) {
		t.Error("operator spamd_address not found")
	}
}

func TestLocateBlocksAndPlacement(t *testing.T) {
	blocks, err := LocateBlocks(generatedConf)
	if err != nil {
		t.Fatal(err)
	}
	want := []Placement{
		{ACL: "acl_smtp_rcpt", Begin: 4, End: 7},
		{ACL: "acl_smtp_data", Begin: 10, End: 14},
		{ACL: "acl_smtp_data", Begin: 28, End: 31},
	}
	if !reflect.DeepEqual(blocks, want) {
		t.Fatalf("blocks = %+v, want %+v", blocks, want)
	}
	if err := CheckPlacement(blocks, "acl_smtp_rcpt", "acl_smtp_data"); err == nil {
		t.Error("missing config block accepted")
	}
	full := append([]Placement{{ACL: "", Begin: 1, End: 3}}, blocks...)
	if err := CheckPlacement(full, "acl_smtp_rcpt", "acl_smtp_data"); err != nil {
		t.Errorf("valid layout rejected: %v", err)
	}
	if err := CheckPlacement(append(full, Placement{ACL: "acl_smtp_mime", Begin: 40}), "acl_smtp_rcpt", "acl_smtp_data"); err == nil {
		t.Error("block in an unexpected ACL accepted")
	}
	for name, conf := range map[string]string{
		"nested":   "# CSM-ANTISPAM BEGIN\n# CSM-ANTISPAM BEGIN\n# CSM-ANTISPAM END\n",
		"no end":   "x\n# CSM-ANTISPAM BEGIN\n",
		"no begin": "# CSM-ANTISPAM END\n",
		"crossing": "# CSM-ANTISPAM BEGIN\nbegin acl\n# CSM-ANTISPAM END\n",
	} {
		if _, err := LocateBlocks(conf); err == nil {
			t.Errorf("%s markers accepted", name)
		}
	}
}
