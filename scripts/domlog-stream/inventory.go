package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

// inventory names each site's verified identity and authoritative log
// copies. The operator writes it from the host's own records; nothing in
// it comes from a request.
type inventory struct {
	Sites          []inventorySite     `json:"sites"`
	TrustedProxies []string            `json:"trusted_proxies"`
	Infrastructure []string            `json:"infrastructure"`
	BotRanges      map[string][]string `json:"bot_ranges"`

	proxies []netip.Prefix
	infra   []netip.Prefix
	bots    map[string][]netip.Prefix
}

type inventorySite struct {
	Name    string   `json:"name"`    // canonical site name, lower-case DNS
	Account string   `json:"account"` // owning hosting account
	Aliases []string `json:"aliases"` // verified hosts of this site, Name included
	Logs    []string `json:"logs"`    // local copies of this site's authoritative domlogs, in order
}

// labelFile assigns operator labels before anonymization. The first rule
// matching a record wins; a record no rule matches stays unlabeled.
type labelFile struct {
	Labels []labelRule `json:"labels"`
}

type labelRule struct {
	Site         string    `json:"site"`
	From         time.Time `json:"from"`
	To           time.Time `json:"to"` // exclusive
	Label        string    `json:"label"`
	Episode      string    `json:"episode,omitempty"`
	Segment      *string   `json:"segment,omitempty"`       // exact decoded first path segment
	NamePrefixes []string  `json:"name_prefixes,omitempty"` // any canonical parameter name with one of these prefixes
}

var (
	dnsName     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	accountName = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,31}$`)
	botName     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	episodeName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errInventory
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInventory
	}
	return nil
}

func parseInventory(b []byte) (*inventory, error) {
	var inv inventory
	if err := decodeStrict(b, &inv); err != nil {
		return nil, err
	}
	if len(inv.Sites) == 0 {
		return nil, errInventory
	}
	names, logs := map[string]bool{}, map[string]bool{}
	for _, s := range inv.Sites {
		if !dnsName.MatchString(s.Name) || names[s.Name] || !accountName.MatchString(s.Account) || len(s.Logs) == 0 {
			return nil, errInventory
		}
		names[s.Name] = true
		hasName := false
		for _, a := range s.Aliases {
			if !dnsName.MatchString(a) {
				return nil, errInventory
			}
			hasName = hasName || a == s.Name
		}
		if !hasName {
			return nil, errInventory
		}
		for _, l := range s.Logs {
			if l == "" || logs[l] {
				return nil, errInventory
			}
			logs[l] = true
		}
	}
	var err error
	if inv.proxies, err = parsePrefixes(inv.TrustedProxies); err != nil {
		return nil, err
	}
	if inv.infra, err = parsePrefixes(inv.Infrastructure); err != nil {
		return nil, err
	}
	inv.bots = map[string][]netip.Prefix{}
	for name, ranges := range inv.BotRanges {
		if !botName.MatchString(name) {
			return nil, errInventory
		}
		if inv.bots[name], err = parsePrefixes(ranges); err != nil {
			return nil, err
		}
	}
	return &inv, nil
}

// parsePrefixes accepts CIDRs and bare addresses; IPv4-mapped IPv6 is IPv4.
func parsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		if p, err := netip.ParsePrefix(s); err == nil {
			if p.Addr().Is4In6() {
				if p.Bits() < 96 {
					return nil, errInventory
				}
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return nil, errInventory
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func containsAddr(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseLabels(b []byte, inv *inventory) ([]labelRule, error) {
	var lf labelFile
	if err := decodeStrict(b, &lf); err != nil {
		return nil, errLabels
	}
	sites := map[string]bool{}
	for _, s := range inv.Sites {
		sites[s.Name] = true
	}
	for _, r := range lf.Labels {
		episodic := r.Label == crawlreplay.LabelAttack || r.Label == crawlreplay.LabelOverload
		switch {
		case !sites[r.Site], !r.From.Before(r.To),
			!episodic && r.Label != crawlreplay.LabelHealthy,
			episodic != (r.Episode != ""),
			r.Episode != "" && !episodeName.MatchString(r.Episode):
			return nil, errLabels
		}
		for _, p := range r.NamePrefixes {
			if p == "" || strings.ToLower(p) != p {
				return nil, errLabels
			}
		}
	}
	return lf.Labels, nil
}
