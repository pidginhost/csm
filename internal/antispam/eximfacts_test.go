package antispam

import (
	"errors"
	"fmt"
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

// Exim 4.100.1 on a cPanel host prints these for an undefined list and exits 0
// (spike 1a); a lookup that cannot read its file exits 1 instead.
func TestParseBeResultSeparatesUndefinedLists(t *testing.T) {
	stdout := "Failed: unable to complete match against \"+csm_no_such_list\": NULL\n"
	for _, stderr := range []string{
		"2026-10-09 08:12:11 unknown named host list \"+csm_no_such_list\"\n",
		"2026-10-09 08:12:11 unknown named domain list \"+csm_no_such_list\"\n",
	} {
		if err := ParseBeResult(stdout, stderr); !errors.Is(err, ErrUndefinedList) {
			t.Errorf("ParseBeResult(%q, %q) = %v, want ErrUndefinedList", stdout, stderr, err)
		}
	}
	for _, bad := range [][2]string{
		{stdout, ""},
		{"y\n", "some warning\n"},
		{"", "failed to open /etc/csm_no_such_file for linear search: No such file or directory\n"},
	} {
		err := ParseBeResult(bad[0], bad[1])
		if err == nil || errors.Is(err, ErrUndefinedList) {
			t.Errorf("ParseBeResult(%q, %q) = %v, want an error other than ErrUndefinedList", bad[0], bad[1], err)
		}
	}
}

// Probe output can carry list contents such as lookup credentials, so errors
// never repeat it.
func TestParseBeResultHidesProbeOutput(t *testing.T) {
	for _, out := range [][2]string{
		{"Failed: lookup user=csm_probe_secret\n", ""},
		{"", "mysql: csm_probe_secret denied\n"},
		{"Failed: x \"+csm_probe_secret\": NULL\n", "unknown named host list \"+csm_probe_secret\"\n"},
	} {
		if err := ParseBeResult(out[0], out[1]); err == nil || strings.Contains(err.Error(), "csm_probe_secret") {
			t.Errorf("ParseBeResult(%q, %q) = %v, want an error without probe text", out[0], out[1], err)
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
	got := ungated(t, generatedConf)
	want := []int{24, 27}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UngatedSpamUses = %v, want %v", got, want)
	}
	clean := strings.Replace(generatedConf, "deny\n    condition = ${if eq {${acl_m0}}", "deny\n    condition = ${perl{spamd_is_available}}\n    condition = ${if eq {${acl_m0}}", 1)
	clean = strings.Replace(clean, "  deny condition = ${if >{${spam_score_int}}{50}}\n", "", 1)
	if got := ungated(t, clean); len(got) != 0 {
		t.Errorf("gated config flagged at %v", got)
	}
}

func TestUngatedSpamUsesEximSyntax(t *testing.T) {
	for _, tc := range []struct {
		name, statement string
		unsafe          bool
	}{
		{"tab after verb", "deny\tcondition = ${if >{$spam_score_int}{50}}", true},
		{"tab separates statements", "warn\n  condition = ${perl{spamd_is_available}}\n  spam = nobody:true\ndeny\tcondition = ${if >{$spam_score_int}{50}}", true},
		{"scan before gate", "warn\n  spam = nobody:true\n  condition = ${perl{spamd_is_available}}", true},
		{"header before gate", "warn\n  add_header = X-Spam-Score: $spam_score_int\n  condition = ${perl{spamd_is_available}}", true},
		{"log is not a gate", "deny\n  log_message = ${perl{spamd_is_available}}\n  condition = ${if >{$spam_score_int}{50}}", true},
		{"inverted gate", "deny\n  !condition = ${perl{spamd_is_available}}\n  condition = ${if >{$spam_score_int}{50}}", true},
		{"compound expression is not a gate", "deny\n  condition = ${if eq{${perl{spamd_is_available}}}{0}{yes}{no}}\n  condition = ${if >{$spam_score_int}{50}}", true},
		{"conditional gate", "warn\n.ifdef OPTIONAL_GATE\n  condition = ${perl{spamd_is_available}}\n.endif\n  spam = nobody:true", true},
		{"gate from another branch", "warn\n.ifdef OPTIONAL_GATE\n  condition = ${perl{spamd_is_available}}\n.else\n  spam = nobody:true\n.endif", true},
		{"require rejects when gate fails", "require\n  condition = ${perl{spamd_is_available}}\n  condition = ${if <{$spam_score_int}{50}}", true},
		{"continued verb", "de\\\n  ny condition = ${if >{$spam_score_int}{50}}", true},
		{"continued spam condition", "warn\n  sp\\\n  am = nobody:true", true},
		{"plain gate", "warn\n  condition = ${perl{spamd_is_available}}\n  spam = nobody:true\n  add_header = X-Spam-Score: $spam_score_int", false},
		{"continued gate", "warn\n  condition = \\\n    ${perl{spamd_is_available}}\n  spam = nobody:true", false},
		{"comment within continued gate", "warn\n  condition = \\\n# explanation\n    ${perl{spamd_is_available}}\n  spam = nobody:true", false},
		{"enclosing gate", "warn\n  condition = ${perl{spamd_is_available}}\n.ifdef EXTRA_HEADER\n  add_header = X-Spam-Score: $spam_score_int\n.endif\n  spam = nobody:true", false},
		{"repeated nested gate", "warn\n  condition = ${perl{spamd_is_available}}\n.ifdef OPTIONAL_GATE\n  condition = ${perl{spamd_is_available}}\n.endif\n  spam = nobody:true", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := "begin acl\ncheck_data:\n" + tc.statement + "\n"
			got := ungated(t, conf)
			if tc.unsafe {
				want := []int{3}
				if tc.name == "tab separates statements" {
					want = []int{6}
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("UngatedSpamUses = %v, want %v", got, want)
				}
			} else if len(got) != 0 {
				t.Fatalf("gated statement flagged at %v", got)
			}
		})
	}
}

func TestUngatedSpamUsesSpacedSection(t *testing.T) {
	for _, section := range []string{"begin   acl", "begin acls", "BEGIN acl"} {
		conf := section + "\ncheck_data:\ndeny condition = ${if >{$spam_score_int}{50}}\n"
		if got, want := ungated(t, conf), []int{3}; !reflect.DeepEqual(got, want) {
			t.Errorf("%q: UngatedSpamUses = %v, want %v", section, got, want)
		}
	}
}

func TestUngatedSpamUsesMacros(t *testing.T) {
	conf := "SCAN = spam = nobody:true\nSCORE = $spam_score_int\nGATE = condition = ${perl{spamd_is_available}}\nbegin acl\ncheck_data:\nwarn SCAN\ndeny condition = ${if >{SCORE}{50}}\n"
	if got, want := ungated(t, conf), []int{6, 7}; !reflect.DeepEqual(got, want) {
		t.Fatalf("UngatedSpamUses = %v, want %v", got, want)
	}
	clean := strings.Replace(conf, "warn SCAN", "warn GATE\n  SCAN", 1)
	clean = strings.Replace(clean, "deny condition =", "deny GATE\n  condition =", 1)
	if got := ungated(t, clean); len(got) != 0 {
		t.Fatalf("gated macro uses flagged at %v", got)
	}
	conditional := "GATE = condition = ${perl{spamd_is_available}}\n.ifdef INVERT_GATE\nGATE == !condition = ${perl{spamd_is_available}}\n.endif\nbegin acl\ncheck_data:\nwarn GATE\n  spam = nobody:true\n"
	if got, want := ungated(t, conditional), []int{7}; !reflect.DeepEqual(got, want) {
		t.Fatalf("conditional macro: UngatedSpamUses = %v, want %v", got, want)
	}
}

func TestHasCutthroughControls(t *testing.T) {
	for _, tc := range []struct {
		conf string
		want bool
	}{
		{"warn\n  logwrite = cutthrough_delivery is disabled\n", false},
		{"CUTTHROUGH_OPTION = cutthrough_delivery\n", false},
		{"CUTTHROUGH_OPTION = cutthrough_delivery\nwarn\n  control = CUTTHROUGH_OPTION\n", true},
		{"CUTTHROUGH_CONTROL = control = cutthrough_delivery\nwarn CUTTHROUGH_CONTROL\n", true},
		{"warn\n  control = cutthrough_delivery/defer=pass\n", true},
		{"accept\tcontrol = cutthrough_delivery\n", true},
		{"warn\n  con\\\n  trol = cutthrough_delivery\n", true},
		{"warn\n  control = cutthrough_\\\n  delivery\n", true},
	} {
		if got := cutthrough(t, tc.conf); got != tc.want {
			t.Errorf("HasCutthrough(%q) = %v, want %v", tc.conf, got, tc.want)
		}
	}
}

func TestForeignSpamdAddressContinuation(t *testing.T) {
	local := "@CONFIG@\nspamd_\\\n  address = /run/rspamd/operator.sock\n"
	if !foreign(t, local) {
		t.Fatal("continued operator spamd_address not found")
	}
	if foreign(t, MarkerBegin+"\n"+local+MarkerEnd+"\n") {
		t.Fatal("continued CSM spamd_address counted as foreign")
	}
}

func TestForeignSpamdAddressHiddenOption(t *testing.T) {
	if !foreign(t, "@CONFIG@\nhide spamd_address = /run/rspamd/operator.sock\n") {
		t.Fatal("hidden operator spamd_address not found")
	}
}

func TestForeignSpamdAddressMacro(t *testing.T) {
	conf := "SCANNER = hide spamd_address = /run/rspamd/operator.sock\nSCANNER\n"
	if !foreign(t, conf) {
		t.Fatal("operator scanner macro not found")
	}
	if foreign(t, MarkerBegin+"\n"+conf+MarkerEnd+"\n") {
		t.Fatal("CSM scanner macro counted as foreign")
	}
}

func TestHasCutthroughAndForeignSpamdAddress(t *testing.T) {
	if cutthrough(t, generatedConf) {
		t.Error("no cutthrough in fixture")
	}
	if !cutthrough(t, "acl_smtp_rcpt:\n  accept control = cutthrough_delivery\n") {
		t.Error("cutthrough control not found")
	}
	if cutthrough(t, "# control = cutthrough_delivery\n") {
		t.Error("comment counted as cutthrough")
	}
	local := "@CONFIG@\n# CSM-ANTISPAM BEGIN\nspamd_address = /run/rspamd/csm-normal.sock variant=rspamd tmo=30s\n# CSM-ANTISPAM END\n\n@DIRECTOREND@\n"
	if foreign(t, local) {
		t.Error("CSM's own spamd_address counted as foreign")
	}
	if !foreign(t, strings.Replace(local, "@DIRECTOREND@", "spamd_address = 127.0.0.1 783\n@DIRECTOREND@", 1)) {
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

func TestLocateBlocksRejectsWrongSections(t *testing.T) {
	for name, conf := range map[string]string{
		"cross ACL":             "begin acl\ncheck_rcpt:\n" + MarkerBegin + "\ncheck_data:\n" + MarkerEnd + "\n",
		"cross spaced section":  MarkerBegin + "\nbegin   routers\n" + MarkerEnd + "\n",
		"router block":          "begin routers\nlocaluser:\n" + MarkerBegin + "\n" + MarkerEnd + "\n",
		"unnamed ACL":           "begin acl\n" + MarkerBegin + "\n" + MarkerEnd + "\n",
		"begin in continuation": "spamd_address = \\\n" + MarkerBegin + "\n/run/rspamd/operator.sock\n" + MarkerEnd + "\n",
		"end in continuation":   MarkerBegin + "\nspamd_address = \\\n" + MarkerEnd + "\n/run/rspamd/operator.sock\n",
		"macro ACL boundary":    "NEXT_ACL = check_data:\nbegin acl\ncheck_rcpt:\n" + MarkerBegin + "\nNEXT_ACL\n" + MarkerEnd + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LocateBlocks(conf); err == nil {
				t.Fatal("invalid CSM block accepted")
			}
		})
	}
}

func TestLocateBlocksEximSyntax(t *testing.T) {
	for _, section := range []string{"begin   acl", "begin acls", "BEGIN acl"} {
		conf := section + "\ncheck_data :\n" + MarkerBegin + "\n" + MarkerEnd + "\n"
		got, err := LocateBlocks(conf)
		if err != nil {
			t.Errorf("%q: %v", section, err)
			continue
		}
		want := []Placement{{ACL: "check_data", Begin: 3, End: 4}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: blocks = %+v, want %+v", section, got, want)
		}
	}
}

func TestLocateBlocksMacroACL(t *testing.T) {
	conf := "ACL_NAME = check_data:\nbegin acl\nACL_NAME\n" + MarkerBegin + "\n" + MarkerEnd + "\n"
	got, err := LocateBlocks(conf)
	if err != nil {
		t.Fatal(err)
	}
	want := []Placement{{ACL: "check_data", Begin: 4, End: 5}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("blocks = %+v, want %+v", got, want)
	}
	ambiguous := strings.Replace(conf, "begin acl", ".ifdef OTHER_ACL\nACL_NAME == other_data:\n.endif\nbegin acl", 1)
	if _, err := LocateBlocks(ambiguous); err == nil {
		t.Fatal("ambiguous ACL ownership accepted")
	}
	mixed := "LINE = warn\n.ifdef OTHER_ACL\nLINE == check_data:\n.endif\nbegin acl\ncheck_rcpt:\nLINE\n" + MarkerBegin + "\n" + MarkerEnd + "\n"
	if _, err := LocateBlocks(mixed); err == nil {
		t.Fatal("optional macro ACL boundary accepted")
	}
}

func ungated(t *testing.T, conf string) []int {
	t.Helper()
	lines, err := UngatedSpamUses(conf)
	if err != nil {
		t.Fatalf("UngatedSpamUses: %v", err)
	}
	return lines
}

func cutthrough(t *testing.T, conf string) bool {
	t.Helper()
	found, err := HasCutthrough(conf)
	if err != nil {
		t.Fatalf("HasCutthrough: %v", err)
	}
	return found
}

func foreign(t *testing.T, local string) bool {
	t.Helper()
	found, err := ForeignSpamdAddress(local)
	if err != nil {
		t.Fatalf("ForeignSpamdAddress: %v", err)
	}
	return found
}

// eximParsers runs every config parser on conf and returns their errors.
func eximParsers(conf string) map[string]error {
	_, errU := UngatedSpamUses(conf)
	_, errC := HasCutthrough(conf)
	_, errF := ForeignSpamdAddress(conf)
	_, errL := LocateBlocks(conf)
	return map[string]error{"UngatedSpamUses": errU, "HasCutthrough": errC, "ForeignSpamdAddress": errF, "LocateBlocks": errL}
}

// CSM cannot follow included files, so an include makes the whole file
// unverifiable rather than silently unchecked.
func TestEximParsersRejectIncludes(t *testing.T) {
	for _, directive := range []string{".include /etc/exim_extra.conf", ".include_if_exists /etc/exim_extra.conf"} {
		conf := "begin acl\nacl_smtp_data:\n" + directive + "\n  accept\n"
		for name, err := range eximParsers(conf) {
			if !errors.Is(err, ErrUnverifiable) {
				t.Errorf("%s with %q: err = %v, want ErrUnverifiable", name, directive, err)
			}
		}
	}
}

// Conditional redefinitions multiply macro variants and self-referencing
// macros double a line per definition. Both must stop at a bound instead of
// exhausting memory in the daemon.
func TestEximParsersBoundMacroExpansion(t *testing.T) {
	var fanout strings.Builder
	var uses []string
	for i := 0; i < 22; i++ {
		name := fmt.Sprintf("M%d", i)
		fmt.Fprintf(&fanout, "%s = a\n.ifdef X\n%s = b\n.endif\n", name, name)
		uses = append(uses, name)
	}
	fanout.WriteString("begin acl\nacl_smtp_data:\n  warn condition = " + strings.Join(uses, " ") + "\n")

	var doubling strings.Builder
	doubling.WriteString("A = x\n")
	for i := 0; i < 26; i++ {
		doubling.WriteString("A == A A\n")
	}
	doubling.WriteString("begin acl\nacl_smtp_data:\n  warn condition = A\n")

	for label, conf := range map[string]string{"fan-out": fanout.String(), "doubling": doubling.String()} {
		for name, err := range eximParsers(conf) {
			if !errors.Is(err, ErrUnverifiable) {
				t.Errorf("%s on %s config: err = %v, want ErrUnverifiable", name, label, err)
			}
		}
	}
}

// Exim's .elifdef and .elifndef start a new branch like .else, so a gate in
// the earlier branch does not protect a use in the later one.
func TestUngatedSpamUsesElifBranches(t *testing.T) {
	for _, directive := range []string{".elifdef B", ".elifndef B"} {
		conf := "begin acl\nacl_smtp_data:\nwarn\n.ifdef A\n  condition = ${perl{spamd_is_available}}\n" +
			directive + "\n  spam = nobody:true\n.endif\n"
		if got, want := ungated(t, conf), []int{3}; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: UngatedSpamUses = %v, want %v", directive, got, want)
		}
	}
}

// A line after the END marker that is not a new statement extends CSM's last
// statement in Exim, so the block can no longer be identified.
func TestLocateBlocksRejectsStatementContinuingAfterEnd(t *testing.T) {
	block := "begin acl\nacl_smtp_data:\n" + MarkerBegin + "\nwarn\n  set acl_m_csm_score = 0\n" + MarkerEnd + "\n"
	if _, err := LocateBlocks(block + "# comment\n  add_header = X-Spam-Score: $spam_score_int\n  accept\n"); err == nil || errors.Is(err, ErrUnverifiable) {
		t.Errorf("continuation after END: err = %v, want a marker error", err)
	}
	for name, next := range map[string]string{
		"verb":      "# comment\n  accept\n",
		"directive": ".ifdef X\n  accept\n.endif\n",
		"acl":       "acl_smtp_mime:\n  accept\n",
		"section":   "begin routers\n",
		"eof":       "",
	} {
		if _, err := LocateBlocks(block + next); err != nil {
			t.Errorf("%s after END rejected: %v", name, err)
		}
	}
}
