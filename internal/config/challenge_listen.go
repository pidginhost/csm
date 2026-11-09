package config

import (
	"fmt"
	"strings"

	"github.com/pidginhost/csm/internal/netutil"
)

// ChallengeSocketExample is the socket form messages and docs point at.
const ChallengeSocketExample = "unix:/run/csm/challenge.sock"

const challengeSocketPrefix = "unix:"

// ChallengeSocketPath reports whether challenge.listen_addr asks for a Unix
// socket and returns its path, unvalidated. Every reader of listen_addr asks
// this first, so socket mode is recognised in one place.
func ChallengeSocketPath(listenAddr string) (string, bool) {
	addr := strings.TrimSpace(listenAddr)
	if len(addr) < len(challengeSocketPrefix) || !strings.EqualFold(addr[:len(challengeSocketPrefix)], challengeSocketPrefix) {
		return "", false
	}
	return strings.TrimSpace(addr[len(challengeSocketPrefix):]), true
}

// ChallengeLocalTrustError reports a challenge.trusted_proxies entry that
// covers an address of this host. Any local account can connect from such an
// address and write X-Forwarded-For, so trusting it lets it pose as any
// visitor. Validation, the server, the installer and doctor share this text.
func ChallengeLocalTrustError(entries []string) error {
	entry, covered, err := netutil.HostLocalProxyEntry(entries)
	if err != nil {
		return fmt.Errorf("challenge.trusted_proxies: cannot check the entries: %v", err)
	}
	if entry == "" {
		return nil
	}
	return fmt.Errorf("challenge.trusted_proxies entry %q covers %s, an address of this host: local accounts could pose as any visitor. Point a proxy on this host at challenge.listen_addr: %s with challenge.listen_group, or remove trusted_proxies and use direct mode", entry, covered, ChallengeSocketExample)
}
