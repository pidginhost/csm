// Package inventory enumerates mail forwarders on a host and classifies their
// destinations, so operators can see which accounts relay mail off-server and
// to which providers. It is the canonical home for forwarder-domain logic in
// CSM. Enumeration is platform-abstracted: cPanel reads /etc/valiases, other
// hosts read /etc/aliases, ~/.forward, or postfix virtual maps (wired
// incrementally). Reading the filesystem is injected so the parsing logic is
// testable without root or a live mail server.
package inventory

import "strings"

// ProviderClass labels a forwarder destination by where it delivers. Free
// providers (Yahoo/Gmail/Outlook) are split out because forwarding spam to
// them is what degrades a server's outbound reputation; local stays on-server.
type ProviderClass string

const (
	ProviderLocal    ProviderClass = "local"
	ProviderYahoo    ProviderClass = "yahoo"
	ProviderGmail    ProviderClass = "gmail"
	ProviderOutlook  ProviderClass = "outlook"
	ProviderExternal ProviderClass = "external"
)

// freeProviderDomains maps known free-provider mail domains to their class.
// Matched by exact domain or, for multi-ccTLD families like Yahoo, by the
// leading label (yahoo.*). Lowercase keys; lookups lowercase the input.
var freeProviderExact = map[string]ProviderClass{
	"gmail.com":      ProviderGmail,
	"googlemail.com": ProviderGmail,
	"ymail.com":      ProviderYahoo,
	"rocketmail.com": ProviderYahoo,
	"hotmail.com":    ProviderOutlook,
	"outlook.com":    ProviderOutlook,
	"msn.com":        ProviderOutlook,
}

// freeProviderPrefixes matches provider families that span many ccTLDs
// (yahoo.com, yahoo.co.uk, yahoo.fr; live.com, live.ro; hotmail.co.uk).
var freeProviderPrefixes = map[string]ProviderClass{
	"yahoo.":   ProviderYahoo,
	"hotmail.": ProviderOutlook,
	"outlook.": ProviderOutlook,
	"live.":    ProviderOutlook,
}

// Destination is one resolved target of a forwarder.
type Destination struct {
	Address  string        `json:"address"`
	Domain   string        `json:"domain"`
	Provider ProviderClass `json:"provider"`
}

// Forwarder is a single source address and everything it relays to.
type Forwarder struct {
	Source       string        `json:"source"`       // local_part@domain
	Domain       string        `json:"domain"`       // hosting domain
	Owner        string        `json:"owner"`        // panel account, "" if unknown
	Destinations []Destination `json:"destinations"` // address targets only
	KeepLocal    bool          `json:"keep_local"`   // also delivers to a local mailbox
	ForwardOnly  bool          `json:"forward_only"` // only remote targets, no local copy
}

// HasExternal reports whether any destination leaves the server.
func (f Forwarder) HasExternal() bool {
	for _, d := range f.Destinations {
		if d.Provider != ProviderLocal {
			return true
		}
	}
	return false
}

// HasFreeProvider reports whether any destination is a free-provider mailbox
// (the reputation-risk case).
func (f Forwarder) HasFreeProvider() bool {
	for _, d := range f.Destinations {
		switch d.Provider {
		case ProviderYahoo, ProviderGmail, ProviderOutlook:
			return true
		}
	}
	return false
}

// classifyProvider returns the provider class of a destination address.
// localDomains are the domains hosted on this server (lowercased keys).
func classifyProvider(addr string, localDomains map[string]bool) ProviderClass {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 || at >= len(addr)-1 {
		// No domain: a bare local part is delivered to the local mailbox.
		return ProviderLocal
	}
	domain := strings.ToLower(addr[at+1:])
	if localDomains[domain] {
		return ProviderLocal
	}
	if c, ok := freeProviderExact[domain]; ok {
		return c
	}
	for prefix, c := range freeProviderPrefixes {
		if strings.HasPrefix(domain, prefix) {
			return c
		}
	}
	return ProviderExternal
}

// parseForwarderLine parses one alias/valias line ("local_part: dest[, dest]")
// for the given hosting domain. Returns ok=false for blanks, comments,
// malformed lines, and non-address forwarders (pipes, :fail:, :blackhole:,
// /dev/null) -- those are not mail relayed to a mailbox and carry no
// reputation risk. A line is still returned for purely local aliases so the
// inventory is complete; callers filter on HasExternal as needed.
func parseForwarderLine(domain, line string, localDomains map[string]bool) (Forwarder, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Forwarder{}, false
	}
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return Forwarder{}, false
	}
	localPart := strings.TrimSpace(line[:colon])
	rest := strings.TrimSpace(line[colon+1:])
	if localPart == "" || rest == "" {
		return Forwarder{}, false
	}

	fwd := Forwarder{
		Source: localPart + "@" + domain,
		Domain: domain,
	}
	for _, raw := range strings.Split(rest, ",") {
		dest := strings.TrimSpace(raw)
		if dest == "" || !isAddressDestination(dest) {
			// Pipe / :fail: / :blackhole: / /dev/null / autoresponder:
			// not an address relay. Skip the target but keep the record.
			continue
		}
		fwd.Destinations = append(fwd.Destinations, newDestination(dest, localDomains))
	}
	if len(fwd.Destinations) == 0 {
		return Forwarder{}, false
	}

	localCount := 0
	for _, d := range fwd.Destinations {
		if d.Provider == ProviderLocal {
			localCount++
		}
	}
	fwd.KeepLocal = localCount > 0
	fwd.ForwardOnly = localCount == 0
	return fwd, true
}

// isAddressDestination reports whether a valias destination is a mailbox
// address (as opposed to a pipe, discard, fail, or file delivery).
func isAddressDestination(dest string) bool {
	switch {
	case dest == "":
		return false
	case strings.HasPrefix(dest, "|"): // pipe to a program
		return false
	case strings.HasPrefix(dest, ":"): // :fail:, :blackhole:, :defer:
		return false
	case strings.HasPrefix(dest, "/"): // file / /dev/null
		return false
	case strings.HasPrefix(dest, "\""): // quoted local delivery directive
		return false
	}
	return true
}

func newDestination(addr string, localDomains map[string]bool) Destination {
	domain := ""
	if at := strings.LastIndexByte(addr, '@'); at >= 0 && at < len(addr)-1 {
		domain = strings.ToLower(addr[at+1:])
	}
	return Destination{
		Address:  addr,
		Domain:   domain,
		Provider: classifyProvider(addr, localDomains),
	}
}
