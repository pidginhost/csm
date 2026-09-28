package main

import (
	"net/netip"
	"regexp"
	"time"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

// botEvidence is verified-bot evidence exported from the host's own
// verified-bot list for the recording period: published ranges and DNS
// verdicts, each for one identity and valid over a time interval, with the
// list's source revision and configuration digest. The converter looks
// nothing up; a claim is verified only by a proof for the same identity
// that was valid when the request was logged.
type botEvidence struct {
	FormatVersion int        `json:"format_version"`
	D2Revision    string     `json:"d2_revision"`
	ConfigSHA256  string     `json:"config_sha256"`
	Proofs        []botProof `json:"proofs"`

	ranges map[string][]botProof
	dns    map[string][]botProof
}

type botProof struct {
	Bot     string    `json:"bot"`
	Kind    string    `json:"kind"`              // "range" or "dns"
	Prefix  string    `json:"prefix,omitempty"`  // range proofs
	Addr    string    `json:"addr,omitempty"`    // DNS verdicts
	Verdict string    `json:"verdict,omitempty"` // DNS verdicts: "positive" or "negative"
	From    time.Time `json:"from"`
	To      time.Time `json:"to"` // exclusive

	prefix netip.Prefix
	addr   netip.Addr
}

var (
	lowerHex64  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	revisionHex = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

func parseBotEvidence(b []byte) (*botEvidence, error) {
	var e botEvidence
	if err := crawlreplay.DecodeStrictJSON(b, &e); err != nil {
		return nil, errBotEvidence
	}
	if e.FormatVersion != 1 || !revisionHex.MatchString(e.D2Revision) || !lowerHex64.MatchString(e.ConfigSHA256) || e.Proofs == nil {
		return nil, errBotEvidence
	}
	e.ranges, e.dns = map[string][]botProof{}, map[string][]botProof{}
	for _, p := range e.Proofs {
		if !botName.MatchString(p.Bot) || p.From.IsZero() || !p.From.Before(p.To) {
			return nil, errBotEvidence
		}
		switch {
		case p.Kind == "range" && p.Addr == "" && p.Verdict == "":
			prefixes, err := parsePrefixes([]string{p.Prefix})
			if err != nil || p.Prefix == "" {
				return nil, errBotEvidence
			}
			p.prefix = prefixes[0]
			e.ranges[p.Bot] = append(e.ranges[p.Bot], p)
		case p.Kind == "dns" && p.Prefix == "" && (p.Verdict == "positive" || p.Verdict == "negative"):
			a, err := netip.ParseAddr(p.Addr)
			if err != nil || a.Zone() != "" {
				return nil, errBotEvidence
			}
			p.addr = a.Unmap()
			e.dns[p.Bot] = append(e.dns[p.Bot], p)
		default:
			return nil, errBotEvidence
		}
	}
	return &e, nil
}

func (p botProof) validAt(t time.Time) bool { return !t.Before(p.From) && t.Before(p.To) }

// proof classifies a claim of bot from client at time t. A range of the
// claimed identity verifies it; otherwise a DNS verdict for that exact
// address does. Contradictory verdicts leave the claim unverified.
func (e *botEvidence) proof(bot string, client netip.Addr, t time.Time) string {
	for _, p := range e.ranges[bot] {
		if p.validAt(t) && p.prefix.Contains(client) {
			return crawlreplay.BotProofRange
		}
	}
	positive, negative := false, false
	for _, p := range e.dns[bot] {
		if p.validAt(t) && p.addr == client {
			positive = positive || p.Verdict == "positive"
			negative = negative || p.Verdict == "negative"
		}
	}
	switch {
	case positive && !negative:
		return crawlreplay.BotProofDNS
	case negative && !positive:
		return crawlreplay.BotProofNegative
	}
	return ""
}
