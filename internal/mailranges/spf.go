package mailranges

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// Resolver is the DNS lookup interface used by ResolveSPF. The standard
// library's net.Resolver satisfies this interface; tests supply a fake.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// maxSPFDepth is the maximum recursion depth for include/redirect chains.
// Chains deeper than this are rejected; a well-formed SPF record never needs
// more than a handful of levels, and deeper chains are a sign of misconfiguration
// or an attempt to exhaust resolver resources.
const maxSPFDepth = 10

// maxSPFLookups bounds total DNS TXT lookups during one ResolveSPF call.
// Depth alone does not bound a record that fans out to many unique includes.
const maxSPFLookups = 64

// nonPublicCIDRs lists finite (non-/0) reserved ranges that must never appear
// in a mail-provider SPF record. Default routes (0.0.0.0/0, ::/0) are handled
// separately because they contain every address and would incorrectly reject all
// public prefixes if tested with the Contains-based overlap check.
var nonPublicCIDRs = func() []*net.IPNet {
	ranges := []string{
		"10.0.0.0/8",      // RFC 1918 private
		"172.16.0.0/12",   // RFC 1918 private
		"192.168.0.0/16",  // RFC 1918 private
		"100.64.0.0/10",   // RFC 6598 Shared Address Space
		"127.0.0.0/8",     // loopback (IPv4)
		"::1/128",         // loopback (IPv6)
		"169.254.0.0/16",  // link-local (IPv4)
		"fe80::/10",       // link-local (IPv6)
		"fc00::/7",        // ULA (unique-local)
		"192.0.2.0/24",    // RFC 5737 TEST-NET-1 (documentation)
		"198.51.100.0/24", // RFC 5737 TEST-NET-2 (documentation)
		"203.0.113.0/24",  // RFC 5737 TEST-NET-3 (documentation)
		"2001:db8::/32",   // RFC 3849 (documentation)
	}
	cidrs := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, n, err := net.ParseCIDR(r)
		if err != nil {
			// All entries are compile-time constants; a parse error is a bug.
			panic(fmt.Sprintf("mailranges: bad nonPublicCIDR %q: %v", r, err))
		}
		cidrs = append(cidrs, n)
	}
	return cidrs
}()

// isPublicPrefix reports whether n is routable public address space. It
// returns false for:
//   - Any default route (prefix length 0), either IPv4 or IPv6.
//   - Any prefix whose network address falls within a reserved range.
//   - Any prefix that is a supernet containing a reserved range's network address,
//     so attackers cannot smuggle private space inside a wide covering prefix.
//
// IPv4-mapped IPv6 prefixes (::ffff:<private>/N) are caught by the existing
// IPv4 range checks because Go's net.Contains normalises IPv4-mapped addresses
// to their 4-byte form before comparing against 4-byte reserved ranges.
func isPublicPrefix(n *net.IPNet) bool {
	// Reject default routes: mask with all zero bits in either address family.
	ones, bits := n.Mask.Size()
	if bits > 0 && ones == 0 {
		return false
	}
	// Bidirectional overlap check against every finite reserved range.
	// reserved.Contains(n.IP): n's network address is within the reserved range.
	// n.Contains(reserved.IP): n is a supernet that contains a reserved range.
	for _, reserved := range nonPublicCIDRs {
		if reserved.Contains(n.IP) || n.Contains(reserved.IP) {
			return false
		}
	}
	return true
}

// spfRecord holds the result of parsing one SPF TXT string. It carries only
// the token types ResolveSPF cares about; all other mechanisms (a, mx, ptr,
// exists, qualifiers) are silently ignored because they reference the domain
// itself, not static CIDR blocks useful for DoS-exempt range building.
type spfRecord struct {
	nets     []*net.IPNet
	includes []string
	redirect string // at most one per record
}

// parseSPFRecord parses a single SPF TXT record string and returns its tokens.
// It makes no network calls; all recursion lives in ResolveSPF. Records that
// do not begin with "v=spf1" are rejected. Malformed ip4:/ip6: CIDRs cause an
// error so ResolveSPF falls back to the last-good provider set rather than
// silently omitting them.
func parseSPFRecord(txt string) (spfRecord, error) {
	fields := strings.Fields(txt)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "v=spf1") {
		return spfRecord{}, fmt.Errorf("spf: not a v=spf1 record")
	}

	var rec spfRecord
	var hasRedirect bool
	for _, tok := range fields[1:] {
		rawLower := strings.ToLower(tok)
		if strings.HasPrefix(rawLower, "redirect=") {
			// Track presence with a separate flag: an empty first redirect=
			// value must not let a second redirect= slip past the guard.
			if hasRedirect {
				return spfRecord{}, fmt.Errorf("spf: multiple redirect= directives in one record")
			}
			hasRedirect = true
			rec.redirect = tok[9:]
			if rec.redirect == "" {
				return spfRecord{}, fmt.Errorf("spf: empty redirect= directive")
			}
			continue
		}

		mech, pass, hadQualifier := spfMechanismToken(tok)
		lower := strings.ToLower(mech)
		if hadQualifier && strings.HasPrefix(lower, "redirect=") {
			return spfRecord{}, fmt.Errorf("spf: redirect= directive cannot carry a qualifier")
		}
		if !pass {
			continue
		}
		switch {
		case strings.HasPrefix(lower, "ip4:"):
			cidr := mech[4:]
			n, err := parseSPFIPNet("ip4", cidr)
			if err != nil {
				return spfRecord{}, fmt.Errorf("spf: bad ip4 prefix %q: %w", cidr, err)
			}
			rec.nets = append(rec.nets, n)

		case strings.HasPrefix(lower, "ip6:"):
			cidr := mech[4:]
			n, err := parseSPFIPNet("ip6", cidr)
			if err != nil {
				return spfRecord{}, fmt.Errorf("spf: bad ip6 prefix %q: %w", cidr, err)
			}
			rec.nets = append(rec.nets, n)

		case strings.HasPrefix(lower, "include:"):
			domain := mech[8:]
			if domain == "" {
				return spfRecord{}, fmt.Errorf("spf: empty include directive")
			}
			rec.includes = append(rec.includes, domain)
		}
		// All other tokens (all, a, mx, ptr, exists, qualifiers) are ignored.
	}
	return rec, nil
}

// spfMechanismToken returns the mechanism token after SPF qualifier handling.
// Only pass mechanisms (no qualifier or explicit '+') can contribute ranges.
func spfMechanismToken(tok string) (mech string, pass bool, hadQualifier bool) {
	if tok == "" {
		return "", false, false
	}
	switch tok[0] {
	case '+':
		return tok[1:], true, true
	case '-', '~', '?':
		return tok[1:], false, true
	default:
		return tok, true, false
	}
}

func parseSPFIPNet(family, value string) (*net.IPNet, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty prefix")
	}
	if strings.Contains(value, "/") {
		_, n, err := net.ParseCIDR(value)
		if err != nil {
			return nil, err
		}
		return normalizeSPFIPNetFamily(family, n)
	}

	ip := net.ParseIP(value)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address")
	}
	switch family {
	case "ip4":
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("not an IPv4 prefix")
		}
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}, nil
	case "ip6":
		if ip.To4() != nil {
			return nil, fmt.Errorf("not an IPv6 prefix")
		}
		ip16 := ip.To16()
		if ip16 == nil {
			return nil, fmt.Errorf("not an IPv6 prefix")
		}
		return &net.IPNet{IP: ip16, Mask: net.CIDRMask(128, 128)}, nil
	default:
		return nil, fmt.Errorf("unknown SPF IP family %q", family)
	}
}

func normalizeSPFIPNetFamily(family string, n *net.IPNet) (*net.IPNet, error) {
	_, bits := n.Mask.Size()
	switch family {
	case "ip4":
		ip4 := n.IP.To4()
		if ip4 == nil || bits != 32 {
			return nil, fmt.Errorf("not an IPv4 prefix")
		}
		n.IP = ip4
		return n, nil
	case "ip6":
		if n.IP.To4() != nil || bits != 128 {
			return nil, fmt.Errorf("not an IPv6 prefix")
		}
		ip16 := n.IP.To16()
		if ip16 == nil {
			return nil, fmt.Errorf("not an IPv6 prefix")
		}
		n.IP = ip16
		return n, nil
	default:
		return nil, fmt.Errorf("unknown SPF IP family %q", family)
	}
}

// ResolveSPF resolves the SPF record for root, following include: and redirect=
// directives recursively up to maxSPFDepth levels. It collects all ip4: and
// ip6: prefixes found across the chain, rejects non-public prefixes, detects
// loops, and de-duplicates the result.
//
// The function returns an error rather than partial results on any anomaly
// (loop, depth exceeded, malformed TXT, non-public prefix, malformed CIDR) so
// callers can keep the last-good set instead of publishing a poisoned one.
func ResolveSPF(ctx context.Context, r Resolver, root string) ([]*net.IPNet, error) {
	st := &spfResolveState{
		onPath: make(map[string]bool),
		memo:   make(map[string][]*net.IPNet),
	}
	nets, err := resolveSPFRec(ctx, r, root, st, 0)
	if err != nil {
		return nil, err
	}
	return dedupNets(nets), nil
}

// spfResolveState carries the per-resolution bookkeeping shared across the
// recursive walk. onPath holds the domains on the current DFS branch so a true
// ancestor cycle errors, while memo caches fully-resolved domains so a diamond
// (the same sub-domain reached via two different include branches) resolves once
// and is reused instead of being mistaken for a loop.
type spfResolveState struct {
	onPath  map[string]bool
	memo    map[string][]*net.IPNet
	lookups int
}

// resolveSPFRec is the internal recursive worker for ResolveSPF. It returns the
// prefixes collected from domain's record and everything it transitively
// references.
func resolveSPFRec(ctx context.Context, r Resolver, domain string, st *spfResolveState, depth int) ([]*net.IPNet, error) {
	// A domain present on the current branch is a genuine ancestor cycle.
	if st.onPath[domain] {
		return nil, fmt.Errorf("spf: include/redirect loop detected at %q", domain)
	}
	// A fully-resolved domain reached again off-path is a diamond, not a loop;
	// reuse its cached result without re-querying or re-counting depth.
	if cached, ok := st.memo[domain]; ok {
		return cached, nil
	}
	// Depth bounds only NEW resolutions; cached/cyclic cases are handled above.
	if depth >= maxSPFDepth {
		return nil, fmt.Errorf("spf: depth limit (%d) exceeded at %q", maxSPFDepth, domain)
	}
	if st.lookups >= maxSPFLookups {
		return nil, fmt.Errorf("spf: DNS lookup limit (%d) exceeded at %q", maxSPFLookups, domain)
	}
	st.lookups++

	// Check context before every network call so callers can abort the chain.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	txts, err := r.LookupTXT(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("spf: lookup %q: %w", domain, err)
	}

	// Select exactly one SPF record. Match only an exact "v=spf1" or a
	// "v=spf1 " prefix so a malformed "v=spf1foo..." string is not selected
	// over a real later record.
	var spfTxt string
	for _, t := range txts {
		if isSPFTXT(t) {
			if spfTxt != "" {
				return nil, fmt.Errorf("spf: multiple v=spf1 records for %q", domain)
			}
			spfTxt = t
		}
	}
	if spfTxt == "" {
		return nil, fmt.Errorf("spf: no v=spf1 record for %q", domain)
	}

	rec, err := parseSPFRecord(spfTxt)
	if err != nil {
		return nil, err
	}

	// Enter the branch; leave it on return so siblings can revisit shared nodes.
	st.onPath[domain] = true
	defer delete(st.onPath, domain)

	// Validate and collect ip4:/ip6: prefixes before recursing so a bad record
	// causes an immediate error rather than a partial result.
	var collected []*net.IPNet
	for _, n := range rec.nets {
		if !isPublicPrefix(n) {
			return nil, fmt.Errorf("spf: non-public prefix %s in record for %q", n, domain)
		}
		collected = append(collected, n)
	}

	// Recurse into includes.
	for _, inc := range rec.includes {
		sub, err := resolveSPFRec(ctx, r, inc, st, depth+1)
		if err != nil {
			return nil, err
		}
		collected = append(collected, sub...)
	}

	// Follow redirect= (at most one per record, enforced by parseSPFRecord).
	if rec.redirect != "" {
		sub, err := resolveSPFRec(ctx, r, rec.redirect, st, depth+1)
		if err != nil {
			return nil, err
		}
		collected = append(collected, sub...)
	}

	// Cache only on full success so a partially-resolved domain is never reused.
	st.memo[domain] = collected
	return collected, nil
}

func isSPFTXT(txt string) bool {
	lower := strings.ToLower(txt)
	return lower == "v=spf1" || strings.HasPrefix(lower, "v=spf1 ")
}

// dedupNets returns nets with duplicate prefixes (by CIDR string) removed.
// Order of first occurrence is preserved.
func dedupNets(nets []*net.IPNet) []*net.IPNet {
	if len(nets) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(nets))
	out := make([]*net.IPNet, 0, len(nets))
	for _, n := range nets {
		key := n.String()
		if !seen[key] {
			seen[key] = true
			out = append(out, n)
		}
	}
	return out
}
