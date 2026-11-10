package config

import (
	"fmt"
	"path/filepath"
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

// ChallengeSocketMaxPath is the longest socket path a client can connect to:
// sun_path holds 108 bytes including the terminating NUL.
const ChallengeSocketMaxPath = 107

// ChallengeSocketBindName is the name the server binds before renaming the
// socket into place: a fresh directory named ChallengeSocketBindPrefix plus
// up to ten random digits, holding "s". Its length bounds the directory.
const (
	ChallengeSocketBindPrefix = ".cs"
	challengeSocketBindExtra  = len("/"+ChallengeSocketBindPrefix) + 10 + len("/s")
)

// ChallengeSocketPathError reports a socket path the server cannot bind
// reliably: not absolute, not in clean form, or too long for sun_path once
// the bind-time name is counted. Validation, the installer and the server
// share it, so a path never passes one and fails another.
func ChallengeSocketPathError(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("challenge.listen_addr: unix socket path %q must be absolute", path)
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("challenge.listen_addr: unix socket path %q must be clean (no repeated separators, dot components or trailing slash)", path)
	}
	if len(path) > ChallengeSocketMaxPath {
		return fmt.Errorf("challenge.listen_addr: socket path too long for the %d-byte limit: %s", ChallengeSocketMaxPath, path)
	}
	if dir := filepath.Dir(path); len(dir)+challengeSocketBindExtra > ChallengeSocketMaxPath {
		return fmt.Errorf("challenge.listen_addr: socket directory %s is too long: binding needs %d more bytes within the %d-byte limit", dir, challengeSocketBindExtra, ChallengeSocketMaxPath)
	}
	return nil
}

// ChallengeLocalTrustError reports a challenge.trusted_proxies entry that
// covers an address of this host. Any local account can connect from such an
// address and write X-Forwarded-For, so trusting it lets it pose as any
// visitor. Validation, the server, the installer and doctor share this text.
func ChallengeLocalTrustError(entries []string) error {
	entry, covered, err := netutil.HostLocalProxyEntry(usableTrustedProxyEntries(entries))
	if err != nil {
		return fmt.Errorf("challenge.trusted_proxies: cannot check the entries: %v", err)
	}
	if entry == "" {
		return nil
	}
	return fmt.Errorf("challenge.trusted_proxies entry %q covers %s, an address of this host: local accounts could pose as any visitor. Point a proxy on this host at challenge.listen_addr: %s with challenge.listen_group, or remove trusted_proxies and use direct mode", entry, covered, ChallengeSocketExample)
}
