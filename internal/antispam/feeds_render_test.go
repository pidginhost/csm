package antispam

import (
	"strings"
	"testing"
)

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
	files, _ := RenderFeeds(s)
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
	files, _ = RenderFeeds(s)
	if _, ok := files[RedirectPath(RedirectWhitelist)]; ok || len(files) != 4 {
		t.Fatalf("skipped redirect rendered: %v", files)
	}
}

func TestRenderFeedsDomainRuleShape(t *testing.T) {
	s := defaults(false)
	s.Feeds = []string{FeedSURBL}
	files, _ := RenderFeeds(s)
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
	files, _ := RenderRspamd(s)
	if files["rbl.conf"] != "# csm-managed-version: 1\nenabled = false;\n" {
		t.Errorf("rspamd_maps alone must keep rbl off: %q", files["rbl.conf"])
	}
	if files["phishing.conf"] != "# csm-managed-version: 1\nphishtank_enabled = false;\n" {
		t.Errorf("rspamd_maps keeps phishing's rspamd.com maps: %q", files["phishing.conf"])
	}
	s.Feeds = []string{FeedPSBL}
	files, _ = RenderRspamd(s)
	if files["rbl.conf"] != "# csm-managed-version: 1\nenabled = true;\n" {
		t.Errorf("a DNS feed turns rbl on: %q", files["rbl.conf"])
	}
}
