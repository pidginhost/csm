package checks

import (
	"fmt"
	"net"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// asnLookup resolves an IP to its autonomous system number and organization
// via the GeoLite2-ASN database. The daemon injects it at startup/reload;
// nil (no ASN database, or unit tests that do not exercise the live path)
// disables bad-ASN classification on the outbound connection scan.
var asnLookup func(ip string) (asn uint, org string)

// SetASNLookup wires the GeoLite2-ASN resolver used by the outbound
// connection scan. Passing nil clears it.
func SetASNLookup(fn func(ip string) (asn uint, org string)) { asnLookup = fn }

// EvaluateBadASNOutbound classifies one outbound connection's destination by
// autonomous system and returns a finding when the ASN is bad. It is a pure
// function: the caller supplies the destination IP and the ASN/org already
// resolved from the GeoLite2-ASN database, so the classifier has no IO and
// is the third leg of the host-takeover chain correlator.
//
// Classification:
//   - blocked_asns always flags (e.g. known bulletproof hosters);
//   - when allowed_asns is non-empty, any ASN outside it flags (allowlist
//     mode for hosts whose legitimate egress is confined to a few providers).
//
// An ASN of 0 (no AS found for the IP) is skipped: classifying it would flag
// every destination missing from the ASN database. Private, loopback,
// link-local, and unspecified destinations are skipped because ASN lookup is
// meaningless for them.
func EvaluateBadASNOutbound(cfg *config.Config, dstIP net.IP, asn uint, asOrg string) (alert.Finding, bool) {
	if cfg == nil || !cfg.Detection.BadASNOutbound.Enabled {
		return alert.Finding{}, false
	}
	if dstIP == nil || dstIP.IsLoopback() || dstIP.IsUnspecified() ||
		dstIP.IsPrivate() || dstIP.IsLinkLocalUnicast() || dstIP.IsLinkLocalMulticast() {
		return alert.Finding{}, false
	}
	if asn == 0 {
		return alert.Finding{}, false
	}

	if !asnIsBad(cfg, asn) {
		return alert.Finding{}, false
	}

	org := asOrg
	if org == "" {
		org = "unknown organization"
	}
	dst := dstIP.String()
	if dstIP.To4() == nil {
		dst = "[" + dst + "]"
	}
	return alert.Finding{
		Severity: alert.High,
		Check:    "bad_asn_outbound",
		Message:  fmt.Sprintf("Outbound connection to bad ASN %d (%s): %s", asn, org, dst),
		Details: fmt.Sprintf("Destination: %s\nASN: %d (%s)\n"+
			"Combined with a new uid-0 account or a planted suid binary this escalates to a host takeover.",
			dst, asn, org),
		Timestamp: time.Now(),
	}, true
}

// asnIsBad applies the blocklist-then-allowlist policy to a single ASN.
func asnIsBad(cfg *config.Config, asn uint) bool {
	for _, b := range cfg.Detection.BadASNOutbound.BlockedASNs {
		if b == asn {
			return true
		}
	}
	allowed := cfg.Detection.BadASNOutbound.AllowedASNs
	if len(allowed) == 0 {
		return false
	}
	for _, a := range allowed {
		if a == asn {
			return false
		}
	}
	return true
}
