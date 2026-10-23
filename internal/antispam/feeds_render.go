package antispam

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/pidginhost/csm/internal/ipmap"
)

// Map redirect names, for Settings.SkipMaps (feeds spec section 5.4).
const (
	RedirectForgedRecipients = "forged_recipients"
	RedirectMID              = "mid"
	RedirectMimeTypes        = "mime_types"
	RedirectWhitelist        = "whitelist"
	RedirectMultimap         = "multimap"
)

// MapRedirectNames lists the map redirects in write order.
func MapRedirectNames() []string {
	return []string{RedirectForgedRecipients, RedirectMID, RedirectMimeTypes, RedirectWhitelist, RedirectMultimap}
}

// Optional rspamd files: CSM writes each only while a feed or map redirect
// needs it (feeds spec section 5.2).
const (
	RspamdOverrideDir = "/etc/rspamd/override.d"
	FeedRBLPath       = RspamdOverrideDir + "/rbl.conf"
	FeedRBLGroupPath  = RspamdOverrideDir + "/rbl_group.conf"
	// ScoresPath sets the weight of rspamd's own symbols. CSM leaves it out
	// when the operator owns it.
	ScoresPath = RspamdLocalDir + "/groups.conf"
)

// mapRedirects point rspamd.com maps at rspamd's package copies, or at
// operator files that may not exist; rspamd loads both cleanly. String
// values replace the stock arrays in local.d, where arrays would append.
var mapRedirects = map[string]string{
	RedirectForgedRecipients: "equivalent_domains = \"/etc/rspamd/maps.d/equivalent_domains.inc\";\n",
	RedirectMID:              "source {\n  url = \"/etc/rspamd/maps.d/mid.inc\";\n}\n",
	RedirectMimeTypes:        "file = \"/etc/rspamd/maps.d/mime_types.inc\";\n",
	RedirectWhitelist: "rules {\n" +
		"  WHITELIST_SPF_DKIM {\n    domains = \"/etc/rspamd/maps.d/spf_dkim_whitelist.inc\";\n  }\n" +
		"  WHITELIST_DMARC {\n    domains = \"/etc/rspamd/maps.d/dmarc_whitelist.inc\";\n  }\n}\n",
	RedirectMultimap: multimapRedirects(),
}

func multimapRedirects() string {
	var b strings.Builder
	b.WriteString("redirector {\n  map = \"/etc/rspamd/maps.d/redirectors.inc\";\n}\n")
	for _, kind := range []string{"freemail", "disposable"} {
		for _, part := range []string{"envfrom", "envrcpt", "from", "to", "cc", "replyto", "mdn"} {
			fmt.Fprintf(&b, "%s_%s {\n  map = \"/etc/rspamd/local.d/maps.d/%s.map\";\n}\n", kind, part, kind)
		}
	}
	return b.String()
}

// phishingExceptions points the phishing module's rspamd.com maps at local
// files; it goes into core's phishing.conf.
const phishingExceptions = "exceptions {\n" +
	"  REDIRECTOR_FALSE = \"/etc/rspamd/maps.d/redirectors.inc\";\n" +
	"  PHISHED_WHITELISTED = \"glob;/etc/rspamd/local.d/maps.d/phishing_whitelist.inc\";\n" +
	"}\n"

// RedirectPath is the local.d file of map redirect name.
func RedirectPath(name string) string { return path.Join(RspamdLocalDir, name+".conf") }

// OptionalRspamdPaths lists every optional file in write order: the DNS
// feed files, the map redirects, then the symbol weights.
func OptionalRspamdPaths() []string {
	out := []string{FeedRBLPath, FeedRBLGroupPath}
	for _, name := range MapRedirectNames() {
		out = append(out, RedirectPath(name))
	}
	return append(out, ScoresPath)
}

// RenderFeeds returns the optional files s needs, keyed by path. A path
// absent from the result is one CSM deletes if it wrote it.
func RenderFeeds(s Settings) (map[string]string, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	files := make(map[string]string)
	if feeds := s.DNSFeeds(); len(feeds) > 0 {
		if s.HasFeed(FeedSpamhausDQS) && !validDQSKey(s.DQSKey.Reveal()) {
			return nil, errors.New("feed spamhaus_dqs has no valid key loaded")
		}
		files[FeedRBLPath] = renderRBL(s, feeds)
		files[FeedRBLGroupPath] = renderRBLGroup(feeds)
	}
	for _, name := range MapRedirectNames() {
		text := ""
		if s.Redirects() && !slices.Contains(s.SkipMaps, name) {
			text = mapRedirects[name]
		}
		if name == RedirectMultimap && s.HasFeed(FeedCSMIPMap) {
			text += ipMapRule()
		}
		if text != "" {
			files[RedirectPath(name)] = ManagedHeader + "\n" + text
		}
	}
	return files, nil
}

// ipMapRule is the multimap rule that reads the CSM IP map: each line names
// one of these symbols with a multiplier on the rule's score (spec 6.1).
func ipMapRule() string {
	var names []string
	for _, s := range ipmap.Symbols() {
		names = append(names, strconv.Quote(s.Name))
	}
	return "CSM_IP {\n  type = \"ip\";\n  map = \"" + ipmap.DefaultPath + "\";\n" +
		"  symbols = [" + strings.Join(names, ", ") + "];\n" +
		"  score = " + formatWeight(ipmap.RuleScore) + ";\n  description = \"CSM IP map\";\n}\n"
}

// renderRBL writes only CSM's lists: override.d replaces rspamd's whole
// rbls object. IP rules set every default explicitly, since stock rbl.conf
// adds unknown = true; domain rules follow the stock DBL rule.
func renderRBL(s Settings, feeds []Feed) string {
	var b strings.Builder
	b.WriteString(ManagedHeader + "\nrbls {\n")
	for _, f := range feeds {
		for _, z := range f.Zones {
			zone := strings.ReplaceAll(z.Zone, dqsKeyMark, s.DQSKey.Reveal())
			fmt.Fprintf(&b, "  %s {\n    symbol = \"%s_RULE\";\n    rbl = \"%s\";\n", z.Rule, strings.ToUpper(z.Rule), zone)
			if z.Domain {
				b.WriteString("    ignore_defaults = true;\n    no_ip = true;\n    exclude_users = false;\n    emails_domainonly = true;\n" +
					"    checks = [\"emails\", \"dkim\", \"helo\", \"rdns\", \"replyto\", \"urls\", \"content_urls\"];\n")
				// The emails check extracts body addresses, not sender headers.
				b.WriteString("    selector {\n" +
					"      from_smtp = \"from('smtp'):domain\";\n" +
					"      from_mime = \"from('mime'):domain\";\n" +
					"      mid = \"header(Message-Id).regexp('@([^\\\\.]+\\\\.[^>]+)').last\";\n" +
					"    }\n")
				if z.FullHostname {
					b.WriteString("    url_full_hostname = true;\n")
				}
			} else {
				fmt.Fprintf(&b, "    checks = [\"from\"];\n    ipv4 = %t;\n    ipv6 = %t;\n"+
					"    exclude_local = true;\n    exclude_users = true;\n    unknown = false;\n", z.IPv4, z.IPv6)
			}
			if f.NeedsKey {
				// Keep lookup names, which contain the key, out of the monitor log.
				b.WriteString("    disable_monitoring = true;\n")
			}
			b.WriteString("    returncodes {\n")
			for _, c := range z.Codes {
				fmt.Fprintf(&b, "      %s = [\"%s\"];\n", c.Symbol, strings.Join(c.Answers, "\", \""))
			}
			b.WriteString("    }\n  }\n")
		}
	}
	// The legacy rules alias would otherwise merge unselected lists back in.
	b.WriteString("}\nrules {};\n")
	// attached_maps is SURBL's hashbl map, fetched over plain HTTP whenever
	// rbl runs; only override.d can clear it.
	b.WriteString("attached_maps = [];\n")
	if s.Redirects() {
		b.WriteString("url_whitelist = \"/etc/rspamd/maps.d/surbl-whitelist.inc\";\n" +
			"disabled_rbl_suffixes_map = \"/etc/rspamd/local.d/maps.d/disabled_rbls.inc\";\n")
	}
	return b.String()
}

// renderRBLGroup weights every CSM feed symbol; override.d replaces the
// stock rbl group's symbols, which belong to the lists renderRBL removed.
func renderRBLGroup(feeds []Feed) string {
	var b strings.Builder
	b.WriteString(ManagedHeader + "\nsymbols {\n")
	for _, f := range feeds {
		for _, z := range f.Zones {
			for _, c := range z.Codes {
				fmt.Fprintf(&b, "  \"%s\" {\n    weight = %s;\n    description = \"%s\";\n    one_shot = true;\n  }\n",
					c.Symbol, formatWeight(c.Weight), c.Description)
			}
		}
	}
	b.WriteString("}\n")
	return b.String()
}

func formatWeight(w float64) string {
	s := strconv.FormatFloat(w, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}
