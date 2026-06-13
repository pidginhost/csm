package threatintel

import (
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

// BotEntry is an operator-configured verified bot: claimed-UA substrings
// mapped to the registrable-domain suffixes that forward-confirm it. These
// are additive on top of the built-in allowlist (BotDomains / the
// ClaimedBotFromUA switch / the embedded static IP ranges); operators extend
// coverage for crawlers CSM does not ship -- typically SEO and backlink bots
// -- without a code change. Verification still goes through the same FCrDNS
// check, so a spoofed UA from an unrelated host is never trusted.
type BotEntry struct {
	Name         string
	UASubstrings []string
	RDNSSuffixes []string
}

// operatorBots holds the active operator list. Swapped wholesale on reload;
// readers run on the scan hot path so the pointer load must stay lock-free.
var operatorBots atomic.Pointer[[]BotEntry]

// SetOperatorBots installs the operator-configured bot list. Names,
// substrings, and suffixes are lower-cased and trimmed (leading dots on
// suffixes dropped) so matching is case-insensitive and consistent with the
// built-in tables. Entries without a name or any UA substring are skipped:
// the UA substring is what links a request to the identity.
func SetOperatorBots(entries []BotEntry) {
	norm := normalizeBotEntries(entries, true)
	operatorBots.Store(&norm)
}

func normalizeBotEntries(entries []BotEntry, requireUA bool) []BotEntry {
	norm := make([]BotEntry, 0, len(entries))
	for _, e := range entries {
		ne := BotEntry{Name: normalizeBotName(e.Name)}
		seenUA := map[string]struct{}{}
		for _, raw := range e.UASubstrings {
			s := normalizeUASubstring(raw)
			if s == "" {
				continue
			}
			if _, ok := seenUA[s]; ok {
				continue
			}
			seenUA[s] = struct{}{}
			ne.UASubstrings = append(ne.UASubstrings, s)
		}
		seenSuffix := map[string]struct{}{}
		for _, raw := range e.RDNSSuffixes {
			d := normalizeSuffix(raw)
			if d == "" {
				continue
			}
			if _, ok := seenSuffix[d]; ok {
				continue
			}
			seenSuffix[d] = struct{}{}
			ne.RDNSSuffixes = append(ne.RDNSSuffixes, d)
		}
		if ne.Name == "" || (requireUA && len(ne.UASubstrings) == 0) {
			continue
		}
		norm = append(norm, ne)
	}
	return norm
}

func normalizeBotName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func normalizeUASubstring(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func normalizeSuffix(d string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), ".")
}

func operatorBotEntries() []BotEntry {
	p := operatorBots.Load()
	if p == nil {
		return nil
	}
	return *p
}

// OperatorBotFromUA returns the operator bot identity whose UA substring
// matches ua, or "" if none. Built-in identities are checked first by
// ClaimedBotFromUA; this is the fallback.
func OperatorBotFromUA(lowUA string) string {
	lowUA = strings.ToLower(lowUA)
	for _, e := range operatorBotEntries() {
		for _, s := range e.UASubstrings {
			if strings.Contains(lowUA, s) {
				return e.Name
			}
		}
	}
	return ""
}

func operatorDomains(name string) []string {
	for _, e := range operatorBotEntries() {
		if e.Name == name {
			return e.RDNSSuffixes
		}
	}
	return nil
}

// OperatorBotsCacheVersion folds the operator bot list into the base cache
// logic version. Changing verified_bots therefore changes the stamp the
// daemon hands EnsureBotVerifyLogicVersion, which drops the PTR-verdict cache
// so a previously-spoofed IP is re-checked under the new suffixes instead of
// staying pinned for the cache TTL. The hash is order-independent so the same
// set in a different file order yields the same stamp.
func OperatorBotsCacheVersion(base int, entries []BotEntry) int {
	entries = normalizeBotEntries(entries, false)
	lines := make([]string, 0, len(entries))
	for _, e := range entries {
		subs := append([]string(nil), e.UASubstrings...)
		sufs := append([]string(nil), e.RDNSSuffixes...)
		sort.Strings(subs)
		sort.Strings(sufs)
		lines = append(lines, e.Name+
			"\x00"+strings.Join(subs, ",")+
			"\x00"+strings.Join(sufs, ","))
	}
	sort.Strings(lines)
	h := fnv.New64a()
	_, _ = h.Write([]byte(strconv.Itoa(base)))
	for _, l := range lines {
		_, _ = h.Write([]byte{0x01})
		_, _ = h.Write([]byte(l))
	}
	return int(h.Sum64() & 0x7fffffff)
}
