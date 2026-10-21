package antispam

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Stats endpoint reasons. They are fixed strings so the web UI never shows
// configuration values.
const (
	statsNoListener        = "rspamd's controller has no listener CSM can read without a password; add a private Unix socket (mode 0600, owned by rspamd)"
	statsControllerUnknown = "CSM cannot read rspamd's controller configuration"
)

// StatsEndpoint is where CSM reads rspamd's /stat and /counters without a
// password. Address is empty when there is no such listener; Version is set
// either way.
type StatsEndpoint struct {
	Unix      bool
	Address   string // socket path, or loopback host:port
	RspamdUID int    // uid that must serve the socket; Unix only
	Version   string // from `rspamd --version`
}

// StatsEndpointFor picks rspamd's private controller socket, or else a
// loopback TCP listener that secure_ip trusts. The reason is fixed text,
// set when there is neither.
func StatsEndpointFor(f HostFacts) (StatsEndpoint, string) {
	ep := StatsEndpoint{Version: statsVersion(f.RspamdVersion)}
	if !f.Controller.Present && (f.ControllerErr != nil || f.ControllerUnverifiable != nil) {
		return ep, statsControllerUnknown
	}
	host := f.ControllerHost
	for _, l := range f.Controller.Listeners {
		if !l.Unix || host.RspamdUID < 0 {
			continue
		}
		if s, ok := host.Sockets[l.Path]; ok && s.Err == nil && !s.Missing && s.Socket.UID == host.RspamdUID {
			ep.Unix, ep.Address, ep.RspamdUID = true, l.Path, host.RspamdUID
			return ep, ""
		}
	}
	for _, l := range f.Controller.Listeners {
		if l.Unix {
			continue
		}
		if addr, ok := trustedLoopback(l.HostPort, f.Controller.TrustEntries); ok {
			ep.Address = addr
			return ep, ""
		}
	}
	return ep, statsNoListener
}

var statsLoopbackV4 = netip.MustParseAddr("127.0.0.1")

// trustedLoopback returns the address to dial for a listener bound to a
// loopback literal that a trust entry covers. For localhost CSM dials
// 127.0.0.1. A bind without an explicit port is skipped rather than guessed.
func trustedLoopback(hostPort string, trust []string) (string, bool) {
	host, port, err := net.SplitHostPort(hostPort)
	n, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || n == 0 {
		return "", false
	}
	if strings.EqualFold(host, "localhost") {
		host = statsLoopbackV4.String()
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr != statsLoopbackV4 && addr != netip.IPv6Loopback() {
		return "", false
	}
	for _, entry := range trust {
		// Both IPv4 spellings name the same peer, as in reachable.
		if p, ok := trustPrefix(entry); ok && (p.Contains(addr) || addr.Is4() && p.Contains(netip.AddrFrom16(addr.As16()))) {
			return net.JoinHostPort(addr.String(), port), true
		}
	}
	return "", false
}

// statsVersion is the first line of `rspamd --version`, trimmed, reduced to
// the version number when the line has the usual form.
func statsVersion(r CommandResult) string {
	if r.Err != nil {
		return ""
	}
	line, _, _ := strings.Cut(r.Stdout, "\n")
	line = strings.TrimSpace(line)
	if v, _, err := ParseRspamdVersion(line); err == nil {
		return v
	}
	return line
}

// RuleHits is one symbol's hit count from rspamd's /counters.
type RuleHits struct {
	Symbol string `json:"symbol"`
	Hits   int64  `json:"hits"`
}

// RspamdStats is what the web UI shows from rspamd's /stat and /counters.
type RspamdStats struct {
	Scanned       int64            `json:"scanned"`
	Learned       int64            `json:"learned"`
	HamCount      int64            `json:"ham_count"`
	SpamCount     int64            `json:"spam_count"`
	UptimeSeconds int64            `json:"uptime_seconds"` // 0 = unknown
	Version       string           `json:"version"`
	Actions       map[string]int64 `json:"actions"`
	TopRules      []RuleHits       `json:"top_rules"`
}

// ParseRspamdStat reads the controller's /stat reply. Absent fields stay
// zero and unknown fields are ignored; a known field of the wrong type is
// an error. Errors are fixed text; they never repeat the reply.
func ParseRspamdStat(body []byte) (RspamdStats, error) {
	if t := bytes.TrimSpace(body); len(t) == 0 || t[0] != '{' {
		return RspamdStats{}, errors.New("rspamd's /stat reply is not a JSON object")
	}
	var raw struct {
		Scanned   int64 `json:"scanned"`
		Learned   int64 `json:"learned"`
		HamCount  int64 `json:"ham_count"`
		SpamCount int64 `json:"spam_count"`
		// Some rspamd versions report uptime with a fraction.
		Uptime  float64          `json:"uptime"`
		Version string           `json:"version"`
		Actions map[string]int64 `json:"actions"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return RspamdStats{}, errors.New("rspamd's /stat reply has an invalid field")
	}
	s := RspamdStats{Scanned: raw.Scanned, Learned: raw.Learned, HamCount: raw.HamCount, SpamCount: raw.SpamCount,
		Version: raw.Version, Actions: raw.Actions}
	if raw.Uptime > 0 && raw.Uptime < math.MaxInt64 {
		s.UptimeSeconds = int64(raw.Uptime)
	}
	return s, nil
}

// ParseRspamdCounters reads the controller's /counters reply and returns the
// top symbols by hits, ties by name. Entries without a symbol or a hit are
// skipped. Errors are fixed text; they never repeat the reply.
func ParseRspamdCounters(body []byte, top int) ([]RuleHits, error) {
	if t := bytes.TrimSpace(body); len(t) == 0 || t[0] != '[' {
		return nil, errors.New("rspamd's /counters reply is not a JSON array")
	}
	var entries []RuleHits
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, errors.New("rspamd's /counters reply has an invalid entry")
	}
	entries = slices.DeleteFunc(entries, func(r RuleHits) bool { return r.Symbol == "" || r.Hits <= 0 })
	slices.SortFunc(entries, func(a, b RuleHits) int {
		return cmp.Or(cmp.Compare(b.Hits, a.Hits), strings.Compare(a.Symbol, b.Symbol))
	})
	return slices.Clone(entries[:min(len(entries), max(top, 0))]), nil
}
