package antispam

import (
	"strings"
	"testing"
)

func TestRenderFeedsClearsLegacyRules(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{FeedPSBL}
	files, err := RenderFeeds(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files[FeedRBLPath], "\nrules {};\n") {
		t.Fatal("legacy rules can merge unselected lists back into rbls")
	}
}

func TestRenderFeedsDomainSenderSelectors(t *testing.T) {
	for _, name := range []string{FeedURIBL, FeedSURBL, FeedSpamhausDQS} {
		t.Run(name, func(t *testing.T) {
			s := defaults(false)
			s.Feeds = []string{name}
			s.DQSKeyFile = "/etc/csm/test.key"
			s.DQSKey = NewSecret(strings.Repeat("x", dqsKeyLen))
			files, err := RenderFeeds(s)
			if err != nil {
				t.Fatal(err)
			}
			wantCount := 1
			if name == FeedSpamhausDQS {
				wantCount = 2
			}
			for _, selector := range []string{
				`from_smtp = "from('smtp'):domain";`,
				`from_mime = "from('mime'):domain";`,
				`mid = "header(Message-Id).regexp('@([^\\.]+\\.[^>]+)').last";`,
			} {
				if got := strings.Count(files[FeedRBLPath], selector); got != wantCount {
					t.Errorf("%s rendered %d times, want %d", selector, got, wantCount)
				}
			}
		})
	}
}

func TestRenderFeedsDQSKeyValidation(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{FeedSpamhausDQS}
	s.DQSKeyFile = "/etc/csm/test.key"
	for _, key := range []string{"", strings.Repeat("x", dqsKeyLen-1), strings.Repeat("X", dqsKeyLen), strings.Repeat("x", dqsKeyLen-1) + `"`} {
		s.DQSKey = NewSecret(key)
		files, err := RenderFeeds(s)
		if err == nil || files != nil {
			t.Fatal("invalid DQS key must fail without rendering any files")
		}
		if key != "" && strings.Contains(err.Error(), key) {
			t.Fatal("rendering error discloses the key")
		}
	}
	key := strings.Repeat("x", dqsKeyLen)
	s.DQSKey = NewSecret(key)
	files, err := RenderFeeds(s)
	if err != nil {
		t.Fatal(err)
	}
	for p, content := range files {
		if strings.Contains(content, key) != (p == FeedRBLPath) {
			t.Errorf("%s: key must occur only in the RBL configuration", p)
		}
		if strings.Contains(content, dqsKeyMark) {
			t.Errorf("%s still contains a key placeholder", p)
		}
	}
	for _, zone := range []string{"zen", "dbl", "zrd"} {
		if !strings.Contains(files[FeedRBLPath], `rbl = "`+key+"."+zone+`.dq.spamhaus.net";`) {
			t.Errorf("%s zone was not rendered with the loaded key", zone)
		}
	}
}

const psblRBL = `# csm-managed-version: 1
rbls {
  csm_psbl {
    symbol = "CSM_PSBL_RULE";
    rbl = "psbl.surriel.com";
    checks = ["from"];
    ipv4 = true;
    ipv6 = false;
    exclude_local = true;
    exclude_users = true;
    unknown = false;
    returncodes {
      CSM_PSBL = ["127.0.0.2"];
    }
  }
}
rules {};
attached_maps = [];
url_whitelist = "/etc/rspamd/maps.d/surbl-whitelist.inc";
disabled_rbl_suffixes_map = "/etc/rspamd/local.d/maps.d/disabled_rbls.inc";
`

const psblGroup = `# csm-managed-version: 1
symbols {
  "CSM_PSBL" {
    weight = 2.0;
    description = "PSBL: listed";
    one_shot = true;
  }
}
`

func TestRenderFeedsPSBL(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{FeedPSBL}
	files, err := RenderFeeds(s)
	if err != nil {
		t.Fatal(err)
	}
	if files[FeedRBLPath] != psblRBL {
		t.Errorf("rbl.conf =\n%s\nwant\n%s", files[FeedRBLPath], psblRBL)
	}
	if files[FeedRBLGroupPath] != psblGroup {
		t.Errorf("rbl_group.conf =\n%s\nwant\n%s", files[FeedRBLGroupPath], psblGroup)
	}
}

func TestRenderFeedsRedirectFiles(t *testing.T) {
	files, err := RenderFeeds(defaults(false))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"/etc/rspamd/local.d/forged_recipients.conf": "# csm-managed-version: 1\nequivalent_domains = \"/etc/rspamd/maps.d/equivalent_domains.inc\";\n",
		"/etc/rspamd/local.d/mid.conf":               "# csm-managed-version: 1\nsource {\n  url = \"/etc/rspamd/maps.d/mid.inc\";\n}\n",
		"/etc/rspamd/local.d/mime_types.conf":        "# csm-managed-version: 1\nfile = \"/etc/rspamd/maps.d/mime_types.inc\";\n",
		"/etc/rspamd/local.d/whitelist.conf": "# csm-managed-version: 1\nrules {\n" +
			"  WHITELIST_SPF_DKIM {\n    domains = \"/etc/rspamd/maps.d/spf_dkim_whitelist.inc\";\n  }\n" +
			"  WHITELIST_DMARC {\n    domains = \"/etc/rspamd/maps.d/dmarc_whitelist.inc\";\n  }\n}\n",
	}
	if len(files) != 5 {
		t.Fatalf("rendered %d files without DNS feeds, want the 5 redirects: %v", len(files), files)
	}
	for p, content := range want {
		if files[p] != content {
			t.Errorf("%s =\n%q\nwant\n%q", p, files[p], content)
		}
	}
	mm := files["/etc/rspamd/local.d/multimap.conf"]
	if !strings.HasPrefix(mm, "# csm-managed-version: 1\nredirector {\n  map = \"/etc/rspamd/maps.d/redirectors.inc\";\n}\n") {
		t.Errorf("multimap.conf starts %q", mm)
	}
	for _, rule := range []string{"freemail_envfrom", "freemail_mdn", "disposable_to", "disposable_replyto"} {
		if !strings.Contains(mm, rule+" {\n") {
			t.Errorf("multimap.conf lacks %s", rule)
		}
	}
	if strings.Count(mm, "/etc/rspamd/local.d/maps.d/freemail.map") != 7 || strings.Count(mm, "/etc/rspamd/local.d/maps.d/disposable.map") != 7 {
		t.Error("multimap.conf must point all 14 freemail and disposable rules at local files")
	}
	for p, content := range files {
		if strings.Contains(content, "rspamd.com") {
			t.Errorf("%s names rspamd.com", p)
		}
	}
}

func TestRenderFeedsHonoursRspamdMapsAndSkipMaps(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{FeedPSBL, FeedRspamdMaps}
	files, err := RenderFeeds(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("rspamd_maps must leave only the DNS files: %v", files)
	}
	if strings.Contains(files[FeedRBLPath], "url_whitelist") || strings.Contains(files[FeedRBLPath], "disabled_rbl_suffixes_map") {
		t.Error("rspamd_maps keeps rspamd's rbl maps")
	}
	if !strings.Contains(files[FeedRBLPath], "attached_maps = [];") {
		t.Error("attached_maps must stay off: it is SURBL's plain-HTTP map")
	}
	s = defaults(false)
	s.SkipMaps = []string{RedirectWhitelist}
	files, err = RenderFeeds(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files[RedirectPath(RedirectWhitelist)]; ok || len(files) != 4 {
		t.Fatalf("skipped redirect rendered: %v", files)
	}
}

func TestRenderFeedsDomainRuleShape(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{FeedSURBL}
	files, err := RenderFeeds(s)
	if err != nil {
		t.Fatal(err)
	}
	rbl := files[FeedRBLPath]
	for _, line := range []string{
		`    ignore_defaults = true;`, `    no_ip = true;`, `    exclude_users = false;`, `    emails_domainonly = true;`,
		`    checks = ["emails", "dkim", "helo", "rdns", "replyto", "urls", "content_urls"];`, `    url_full_hostname = true;`,
	} {
		if !strings.Contains(rbl, line+"\n") {
			t.Errorf("surbl rule lacks %q", line)
		}
	}
	group := files[FeedRBLGroupPath]
	if strings.Count(group, "one_shot = true;") != 6 || !strings.Contains(group, "\"CSM_SURBL_CT\" {\n    weight = 0.0;") {
		t.Errorf("rbl_group.conf =\n%s", group)
	}
}

func TestRenderRspamdSwitchesRBLForDNSFeeds(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{FeedRspamdMaps}
	files, err := RenderRspamd(s)
	if err != nil {
		t.Fatal(err)
	}
	if files["rbl.conf"] != "# csm-managed-version: 1\nenabled = false;\n" {
		t.Errorf("rspamd_maps alone must keep rbl off: %q", files["rbl.conf"])
	}
	if files["phishing.conf"] != "# csm-managed-version: 1\nphishtank_enabled = false;\n" {
		t.Errorf("rspamd_maps keeps phishing's rspamd.com maps: %q", files["phishing.conf"])
	}
	s.Feeds = []string{FeedPSBL}
	files, err = RenderRspamd(s)
	if err != nil {
		t.Fatal(err)
	}
	if files["rbl.conf"] != "# csm-managed-version: 1\nenabled = true;\n" {
		t.Errorf("a DNS feed turns rbl on: %q", files["rbl.conf"])
	}
}

func TestRenderFeedsKeyOnlyInRBLFile(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{FeedSpamhausDQS}
	s.DQSKeyFile = "/etc/csm/k"
	if _, err := RenderFeeds(s); err == nil {
		t.Fatal("DQS rendered without a key")
	}
	s.DQSKey = NewSecret(testKey)
	managed, err := ManagedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	for p, content := range managed {
		if strings.Contains(content, testKey) != (p == FeedRBLPath) {
			t.Errorf("%s: key present = %v", p, strings.Contains(content, testKey))
		}
	}
	if !strings.Contains(managed[FeedRBLPath], `rbl = "`+testKey+`.zen.dq.spamhaus.net";`) {
		t.Error("ZEN zone lacks the key")
	}
	if strings.Contains(managed[FeedRBLPath], dqsKeyMark) {
		t.Error("placeholder left in output")
	}
}

// rspamd's monitor logs a failing lookup name, which for DQS carries the
// key; CSM's own probe covers that check instead.
func TestRenderFeedsDQSDisablesMonitoring(t *testing.T) {
	s := defaults(false)
	s.Feeds, s.DQSKeyFile, s.DQSKey = []string{FeedPSBL, FeedSpamhausDQS}, "/etc/csm/k", NewSecret(testKey)
	files, err := RenderFeeds(s)
	if err != nil {
		t.Fatal(err)
	}
	rbl := files[FeedRBLPath]
	if got := strings.Count(rbl, "    disable_monitoring = true;\n"); got != 3 {
		t.Fatalf("disable_monitoring on %d rules, want the 3 DQS rules", got)
	}
	psbl := rbl[strings.Index(rbl, "  csm_psbl {"):]
	psbl = psbl[:strings.Index(psbl, "\n  }\n")]
	if strings.Contains(psbl, "disable_monitoring") {
		t.Error("free lists keep rspamd's monitoring")
	}
}
