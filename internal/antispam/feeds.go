package antispam

import (
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
)

// Feed names an operator can enable (feeds spec section 4.2).
const (
	FeedMailspike   = "mailspike"
	FeedPSBL        = "psbl"
	FeedUCEPROTECT1 = "uceprotect1"
	FeedNordspam    = "nordspam"
	FeedSEM         = "sem"
	FeedSpamCop     = "spamcop"
	FeedBarracuda   = "barracuda"
	FeedDNSWL       = "dnswl"
	FeedURIBL       = "uribl"
	FeedSURBL       = "surbl"
	FeedSpamhausDQS = "spamhaus_dqs"
	FeedRspamdMaps  = "rspamd_maps"
)

// dqsKeyMark is replaced by the operator's Spamhaus DQS key in a zone.
const dqsKeyMark = "{key}"

// Code maps exact DNS answers to one symbol.
type Code struct {
	Symbol      string
	Answers     []string
	Weight      float64
	Description string
}

// Zone is one DNS list, rendered as one rspamd rbl rule.
type Zone struct {
	// Rule is the rbls key; the rule's base symbol is Rule upper-cased with
	// a _RULE suffix and weighs 0.
	Rule string
	Zone string
	// Domain lists check message domains (URLs, emails, HELO, rDNS, DKIM);
	// the others check only the connecting address.
	Domain       bool
	IPv4, IPv6   bool
	FullHostname bool
	Codes        []Code
	// TestName is the listed test point, queried as TestName.Zone; empty
	// means the zone has no documented test point and is not probed.
	TestName    string
	TestAnswers []string
}

// Feed is one catalogue entry.
type Feed struct {
	Name string
	// Zones is empty for rspamd_maps, which only keeps rspamd's map URLs.
	Zones    []Zone
	NeedsKey bool
	// Errors maps answers that mean refusal or misuse to their meaning.
	// They never score; the probe reports them.
	Errors map[string]string
	Terms  string
}

// DNS reports whether f adds rbl rules.
func (f Feed) DNS() bool { return len(f.Zones) > 0 }

func code(symbol string, weight float64, description string, answers ...string) Code {
	return Code{Symbol: symbol, Answers: answers, Weight: weight, Description: description}
}

// ipZone is an IP list with the common RFC 5782 test entry 127.0.0.2.
func ipZone(rule, zone string, ipv6 bool, codes ...Code) Zone {
	return Zone{Rule: rule, Zone: zone, IPv4: true, IPv6: ipv6, Codes: codes,
		TestName: "2.0.0.127", TestAnswers: []string{"127.0.0.2"}}
}

func answerRange(prefix string, from, to int) []string {
	var out []string
	for n := from; n <= to; n++ {
		out = append(out, prefix+strconv.Itoa(n))
	}
	return out
}

type bit struct {
	mask        int
	symbol      string
	weight      float64
	description string
}

// exclusiveBits maps each answer 127.0.0.N whose low (blocked) bit is clear
// to the first bit in order that N sets, so one answer fires one symbol.
// Bits not in order are ignored.
func exclusiveBits(order ...bit) []Code {
	codes := make([]Code, len(order))
	for i, b := range order {
		codes[i] = Code{Symbol: b.symbol, Weight: b.weight, Description: b.description}
	}
	for n := 2; n <= 254; n += 2 {
		for i, b := range order {
			if n&b.mask != 0 {
				codes[i].Answers = append(codes[i].Answers, "127.0.0."+strconv.Itoa(n))
				break
			}
		}
	}
	return codes
}

// dnswlCodes maps 127.0.<category>.<trust> to one symbol per trust level.
// Category 10 holds special cases, including the test entry, and never
// scores.
func dnswlCodes() []Code {
	levels := []Code{
		{Symbol: "CSM_DNSWL_NONE", Weight: 0, Description: "DNSWL: listed, no trust"},
		{Symbol: "CSM_DNSWL_LOW", Weight: -0.1, Description: "DNSWL: low trust"},
		{Symbol: "CSM_DNSWL_MED", Weight: -0.2, Description: "DNSWL: medium trust"},
		{Symbol: "CSM_DNSWL_HI", Weight: -0.5, Description: "DNSWL: high trust"},
	}
	for trust := range levels {
		for category := 1; category <= 20; category++ {
			if category != 10 {
				levels[trust].Answers = append(levels[trust].Answers,
					"127.0."+strconv.Itoa(category)+"."+strconv.Itoa(trust))
			}
		}
	}
	return levels
}

var spamhausErrors = map[string]string{
	"127.255.255.250": "the DQS key is disabled",
	"127.255.255.251": "the DQS key is used from an address Spamhaus does not allow",
	"127.255.255.252": "the query names a zone that does not exist",
	"127.255.255.254": "the query came through a public or open resolver",
	"127.255.255.255": "the query volume is over the allowed limit",
	"127.0.1.255":     "the domain list was asked about an IP address",
	"127.0.2.255":     "the domain age list was asked about an IP address",
}

// catalogue lists every feed (feeds spec section 4.2). Weights start from
// rspamd's stock weights, or Spamhaus's for DQS, capped at 5. SURBL and DQS
// are reduced further so all positive symbols together stay below the
// default reject score. Domain lists can hit several symbols per message;
// consumers must also make each symbol one_shot to bound repeated hits.
var catalogue = []Feed{
	{
		Name: FeedMailspike,
		Zones: []Zone{{Rule: "csm_mailspike", Zone: "rep.mailspike.net", IPv4: true,
			Codes: []Code{
				code("CSM_MAILSPIKE_WORST", 2.0, "Mailspike: worst reputation", "127.0.0.10"),
				code("CSM_MAILSPIKE_VERYBAD", 1.5, "Mailspike: very bad reputation", "127.0.0.11"),
				code("CSM_MAILSPIKE_BAD", 1.0, "Mailspike: bad reputation", "127.0.0.12"),
			},
			TestName: "2.0.0.127", TestAnswers: []string{"127.0.0.2"}}},
		Terms: "Free for sites under 100,000 messages and 100,000 DNS queries a day; contact Mailspike above that.",
	},
	{
		Name:  FeedPSBL,
		Zones: []Zone{ipZone("csm_psbl", "psbl.surriel.com", false, code("CSM_PSBL", 2.0, "PSBL: listed", "127.0.0.2"))},
		Terms: "Free for anyone.",
	},
	{
		Name:  FeedUCEPROTECT1,
		Zones: []Zone{ipZone("csm_uceprotect1", "dnsbl-1.uceprotect.net", false, code("CSM_UCEPROTECT1", 1.5, "UCEPROTECT level 1: listed", "127.0.0.2"))},
		Terms: "Free for private and commercial use; above 100,000 requests a day UCEPROTECT asks for its rsync feed. Level 1 also lists some forwarders that break SPF.",
	},
	{
		Name:  FeedNordspam,
		Zones: []Zone{ipZone("csm_nordspam", "bl.nordspam.com", true, code("CSM_NORDSPAM", 2.0, "Nordspam: listed", "127.0.0.2"))},
		Terms: "Free for commercial and non-commercial use; contact Nordspam above 10,000 queries a day.",
	},
	{
		Name: FeedSEM,
		Zones: []Zone{
			ipZone("csm_sem", "bl.spameatingmonkey.net", false, code("CSM_SEM", 1.0, "Spam Eating Monkey: listed", "127.0.0.2")),
			{Rule: "csm_sem_ipv6", Zone: "bl.ipv6.spameatingmonkey.net", IPv6: true,
				Codes: []Code{code("CSM_SEM_IPV6", 1.0, "Spam Eating Monkey IPv6: listed", "127.0.0.2")}},
		},
		Terms: "Free; for scoring only, never to reject mail on its own. Tell Spam Eating Monkey before going above 100,000 queries a day.",
	},
	{
		Name:  FeedSpamCop,
		Zones: []Zone{ipZone("csm_spamcop", "bl.spamcop.net", false, code("CSM_SPAMCOP", 1.5, "SpamCop: listed", "127.0.0.2"))},
		Terms: "Free; SpamCop calls its list aggressive and recommends tagging, not rejecting.",
	},
	{
		Name:  FeedBarracuda,
		Zones: []Zone{ipZone("csm_barracuda", "b.barracudacentral.org", false, code("CSM_BARRACUDA", 2.0, "Barracuda: listed", "127.0.0.2"))},
		Terms: "Free after registering the addresses of the resolvers that query it with Barracuda.",
	},
	{
		Name: FeedDNSWL,
		Zones: []Zone{{Rule: "csm_dnswl", Zone: "list.dnswl.org", IPv4: true, IPv6: true, Codes: dnswlCodes(),
			TestName: "2.0.0.127", TestAnswers: []string{"127.0.10.0", "127.0.10.1", "127.0.10.2", "127.0.10.3"}}},
		Errors: map[string]string{"127.0.0.255": "DNSWL refuses this resolver: public resolvers and sites over 100,000 queries a day are blocked"},
		Terms:  "Free through DNS under 100,000 queries a day; its pages conflict on non-commercial use. A listing lowers the score slightly.",
	},
	{
		Name: FeedURIBL,
		Zones: []Zone{{Rule: "csm_uribl", Zone: "multi.uribl.com", Domain: true,
			Codes: exclusiveBits(
				bit{2, "CSM_URIBL_BLACK", 5.0, "URIBL: black list"},
				bit{4, "CSM_URIBL_GREY", 2.5, "URIBL: grey list"},
				bit{8, "CSM_URIBL_RED", 0.5, "URIBL: red list"},
			),
			TestName: "test.uribl.com", TestAnswers: []string{"127.0.0.14"}}},
		Errors: map[string]string{"127.0.0.1": "URIBL refuses this resolver", "127.0.0.255": "URIBL refuses this resolver"},
		Terms:  "Free for low-volume use only; URIBL blocks public and large shared resolvers.",
	},
	{
		Name: FeedSURBL,
		Zones: []Zone{{Rule: "csm_surbl", Zone: "multi.surbl.org", Domain: true, FullHostname: true,
			Codes: exclusiveBits(
				bit{8, "CSM_SURBL_PH", 3.5, "SURBL: phishing"},
				bit{16, "CSM_SURBL_MW", 3.5, "SURBL: malware"},
				bit{64, "CSM_SURBL_ABUSE", 3.5, "SURBL: abuse"},
				bit{128, "CSM_SURBL_CRACKED", 3.5, "SURBL: cracked site"},
				bit{32, "CSM_SURBL_CT", 0, "SURBL: click tracker"},
				bit{4, "CSM_SURBL_DM", 0, "SURBL: disposable mail"},
			),
			TestName: "test.surbl.org", TestAnswers: []string{"127.0.0.254"}}},
		Errors: map[string]string{"127.0.0.1": "SURBL refuses this resolver"},
		Terms:  "Free only for organisations under 1,000 users or 250,000 messages a day, and never inside a product or service sold for a fee; other use needs SURBL's paid data service.",
	},
	{
		Name:     FeedSpamhausDQS,
		NeedsKey: true,
		Zones: []Zone{
			{Rule: "csm_dqs_zen", Zone: dqsKeyMark + ".zen.dq.spamhaus.net", IPv4: true, IPv6: true,
				Codes: []Code{code("CSM_DQS_ZEN", 5.0, "Spamhaus ZEN: listed",
					"127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7", "127.0.0.9", "127.0.0.10", "127.0.0.11", "127.0.0.30")},
				TestName: "2.0.0.127", TestAnswers: []string{"127.0.0.2"}},
			{Rule: "csm_dqs_dbl", Zone: dqsKeyMark + ".dbl.dq.spamhaus.net", Domain: true, Codes: []Code{
				code("CSM_DQS_DBL", 3.0, "Spamhaus DBL: spam, phishing, malware or botnet domain", "127.0.1.2", "127.0.1.4", "127.0.1.5", "127.0.1.6"),
				code("CSM_DQS_DBL_ABUSED", 2.0, "Spamhaus DBL: abused legitimate domain", answerRange("127.0.1.", 102, 106)...),
			}},
			{Rule: "csm_dqs_zrd", Zone: dqsKeyMark + ".zrd.dq.spamhaus.net", Domain: true, Codes: []Code{
				code("CSM_DQS_ZRD_VERY_FRESH", 3.0, "Spamhaus ZRD: domain first seen in the last 4 hours", answerRange("127.0.2.", 2, 4)...),
				code("CSM_DQS_ZRD_FRESH", 1.0, "Spamhaus ZRD: domain first seen in the last 24 hours", answerRange("127.0.2.", 5, 24)...),
			}},
		},
		Errors: spamhausErrors,
		Terms:  "Needs a DQS key. The free key covers non-commercial use under 100,000 queries a day; commercial use needs a paid key.",
	},
	{
		Name:  FeedRspamdMaps,
		Terms: "Keeps rspamd's own map downloads from maps.rspamd.com; free use is non-commercial and under 5,000 queries a day, other use needs an agreement with rspamd.",
	},
}

// FeedByName returns an independent copy of the catalogue entry named name.
func FeedByName(name string) (Feed, bool) {
	i := slices.IndexFunc(catalogue, func(f Feed) bool { return f.Name == name })
	if i < 0 {
		return Feed{}, false
	}
	f := catalogue[i]
	f.Errors = maps.Clone(f.Errors)
	f.Zones = slices.Clone(f.Zones)
	for i := range f.Zones {
		z := &f.Zones[i]
		z.TestAnswers = slices.Clone(z.TestAnswers)
		z.Codes = slices.Clone(z.Codes)
		for j := range z.Codes {
			z.Codes[j].Answers = slices.Clone(z.Codes[j].Answers)
		}
	}
	return f, true
}

// FeedNames lists every catalogue name in catalogue order.
func FeedNames() []string {
	out := make([]string, len(catalogue))
	for i, f := range catalogue {
		out[i] = f.Name
	}
	return out
}

// ValidateFeeds checks feed names and the DQS key path: every name is in
// the catalogue once, and spamhaus_dqs needs a clean absolute key file path.
func ValidateFeeds(names []string, keyFile string) error {
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if _, ok := FeedByName(name); !ok {
			return fmt.Errorf("unknown feed; known feeds: %s", strings.Join(FeedNames(), ", "))
		}
		if seen[name] {
			return fmt.Errorf("feed %q is listed twice", name)
		}
		seen[name] = true
	}
	if !seen[FeedSpamhausDQS] {
		return nil
	}
	switch {
	case keyFile == "":
		return errors.New("feed spamhaus_dqs needs spamhaus_dqs_key_file")
	case !path.IsAbs(keyFile) || path.Clean(keyFile) != keyFile:
		return errors.New("spamhaus_dqs_key_file must be a clean absolute path")
	case keyFile == "/" || strings.ContainsRune(keyFile, 0):
		return errors.New("spamhaus_dqs_key_file must be a file path without NUL bytes")
	}
	return nil
}
