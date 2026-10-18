package antispam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// ControllerListener is one bind_socket entry of the loaded controller
// worker. Raw is the entry as rspamd printed it, used as the finding key.
type ControllerListener struct {
	Raw      string
	Unix     bool
	Path     string
	Mode     fs.FileMode
	HostPort string
}

// ControllerConfig is the loaded controller worker. Password values never
// leave ParseControllerConfig; only whether each one is set.
type ControllerConfig struct {
	Present           bool
	Listeners         []ControllerListener
	TrustEntries      []string
	PasswordSet       bool
	EnablePasswordSet bool
}

// ParseControllerConfig reads the controller worker from the full
// `rspamadm configdump -j` output. Errors name the field, never a value.
func ParseControllerConfig(fullDump []byte) (ControllerConfig, error) {
	var cfg ControllerConfig
	root, err := dumpObjectAs[json.RawMessage](fullDump, "worker")
	if err != nil {
		return cfg, err
	}
	section, ok := root["worker"]
	if !ok {
		return cfg, nil
	}
	controller, err := controllerSection(section)
	if err != nil || controller == nil {
		return cfg, err
	}
	fields, err := dumpObjectAs[json.RawMessage](controller, "worker controller")
	if err != nil {
		return cfg, err
	}
	cfg.Present = true
	binds, err := stringOrList(fields, "bind_socket")
	if err != nil {
		return ControllerConfig{}, err
	}
	if len(binds) == 0 {
		return ControllerConfig{}, errors.New("configdump worker controller: bind_socket is missing")
	}
	for _, b := range binds {
		l, err := parseControllerBind(b)
		if err != nil {
			return ControllerConfig{}, err
		}
		cfg.Listeners = append(cfg.Listeners, l)
	}
	if cfg.TrustEntries, err = stringOrList(fields, "secure_ip"); err != nil {
		return ControllerConfig{}, err
	}
	if cfg.PasswordSet, err = passwordSet(fields, "password"); err != nil {
		return ControllerConfig{}, err
	}
	if cfg.EnablePasswordSet, err = passwordSet(fields, "enable_password"); err != nil {
		return ControllerConfig{}, err
	}
	return cfg, nil
}

// controllerSection returns the controller object from the worker section,
// which rspamd prints as a list of single-key objects (4.2) or as an object
// keyed by worker type.
func controllerSection(section json.RawMessage) (json.RawMessage, error) {
	var entries []json.RawMessage
	switch trimmed := bytes.TrimSpace(section); {
	case len(trimmed) > 0 && trimmed[0] == '[':
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			return nil, errors.New("configdump worker: invalid JSON")
		}
	default:
		entries = []json.RawMessage{section}
	}
	var found json.RawMessage
	for _, entry := range entries {
		workers, err := dumpObjectAs[json.RawMessage](entry, "worker")
		if err != nil {
			return nil, err
		}
		c, ok := workers["controller"]
		if !ok {
			continue
		}
		if found != nil {
			return nil, errors.New("configdump worker: more than one controller worker")
		}
		found = c
	}
	return found, nil
}

func stringOrList(fields map[string]json.RawMessage, name string) ([]string, error) {
	raw, ok := fields[name]
	if !ok {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("configdump worker controller: %s is not a string or a list of strings", name)
	}
	return many, nil
}

func passwordSet(fields map[string]json.RawMessage, name string) (bool, error) {
	raw, ok := fields[name]
	if !ok {
		return false, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, fmt.Errorf("configdump worker controller: %s is not a string", name)
	}
	return value != "", nil
}

// parseControllerBind splits "path option=value ..." for Unix sockets and
// keeps host:port forms whole. Only mode= matters for exposure.
func parseControllerBind(raw string) (ControllerListener, error) {
	l := ControllerListener{Raw: raw}
	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return l, errors.New("configdump worker controller: empty bind_socket entry")
	}
	addr := parts[0]
	if !strings.HasPrefix(addr, "/") {
		if strings.Contains(addr, "/") || len(parts) > 1 {
			return l, errors.New("configdump worker controller: bind_socket entry is neither an absolute Unix path nor host:port")
		}
		l.HostPort = addr
		return l, nil
	}
	l.Unix, l.Path = true, filepath.Clean(addr)
	for _, opt := range parts[1:] {
		value, ok := strings.CutPrefix(opt, "mode=")
		if !ok {
			continue
		}
		mode, err := strconv.ParseUint(value, 8, 32)
		if err != nil || mode > 0o7777 {
			return l, errors.New("configdump worker controller: bind_socket mode is not an octal file mode")
		}
		l.Mode = fs.FileMode(mode)
	}
	return l, nil
}

// ControllerHostFacts is what exposure needs beyond the loaded worker:
// host addresses a trust entry could name, the facts of each Unix
// controller socket, and the members of each group that could own one.
type ControllerHostFacts struct {
	Addrs        []netip.Prefix
	Sockets      map[string]SocketFacts
	GroupMembers map[int][]string
	RspamdUID    int
	RspamdGID    int
	RspamdUser   string
}

// Exposure reasons. They are fixed strings so a finding never carries
// configuration values.
const (
	exposureTrusted       = "trusted address reachable by local processes"
	exposureUnresolved    = "unresolved trust entry"
	exposureNoPasswords   = "no passwords configured"
	exposureReadOnly      = "read-only access without password"
	exposureSocket        = "socket reachable by other users"
	exposureSocketParent  = "socket parent writable by other users"
	exposureSocketUnknown = "socket facts unavailable"
)

// Local processes reach these through loopback, whatever the bind address.
var localPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:127.0.0.0/104"),
}

// ControllerExposure returns one Warning per controller listener that a
// tenant process can use. Every TCP listener is reachable from the host, so
// trust entries and passwords decide; a Unix listener grants admin to any
// process that can connect, so its file access decides.
func ControllerExposure(c ControllerConfig, f ControllerHostFacts) []Problem {
	if !c.Present {
		return nil
	}
	var out []Problem
	for _, l := range c.Listeners {
		var reason string
		if l.Unix {
			reason = unixExposure(l, f)
		} else {
			reason = tcpExposure(c, f)
		}
		if reason != "" {
			out = append(out, Problem{Code: CodeControllerOpen, Severity: Warning, Key: l.Raw, Detail: reason})
		}
	}
	return out
}

func tcpExposure(c ControllerConfig, f ControllerHostFacts) string {
	unresolved := false
	for _, entry := range c.TrustEntries {
		prefix, ok := trustPrefix(entry)
		if !ok {
			unresolved = true
			continue
		}
		if reachable(prefix, f.Addrs) {
			return exposureTrusted
		}
	}
	switch {
	case !c.PasswordSet && !c.EnablePasswordSet:
		return exposureNoPasswords
	case unresolved:
		return exposureUnresolved
	case !c.PasswordSet:
		return exposureReadOnly
	}
	return ""
}

// trustPrefix parses a secure_ip entry as an address or CIDR. Maps,
// hostnames and file paths do not parse: CSM cannot see what they hold.
func trustPrefix(entry string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(entry); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(entry); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// reachable also compares each IPv4 address in its IPv4-mapped IPv6 form:
// Overlaps never matches across families, and a trust entry may name a host
// address either way.
func reachable(p netip.Prefix, hostAddrs []netip.Prefix) bool {
	for _, local := range append(slices.Clone(localPrefixes), hostAddrs...) {
		if p.Overlaps(local) {
			return true
		}
		if local.Addr().Is4() && p.Overlaps(netip.PrefixFrom(netip.AddrFrom16(local.Addr().As16()), local.Bits()+96)) {
			return true
		}
	}
	return false
}

func unixExposure(l ControllerListener, f ControllerHostFacts) string {
	s, ok := f.Sockets[l.Path]
	switch {
	case !ok || s.Err != nil:
		return exposureSocketUnknown
	case s.Missing:
		return ""
	}
	trusted := func(uid int) bool { return uid == 0 || uid == f.RspamdUID }
	sock := s.Socket
	perm := sock.Mode.Perm()
	switch {
	case !trusted(sock.UID), sock.ExtACL, perm&0o002 != 0:
		return exposureSocket
	case perm&0o020 != 0 && f.groupHasOthers(sock.GID):
		return exposureSocket
	}
	for _, p := range s.Parents {
		if !trusted(p.UID) || p.ExtACL || p.Mode.Perm()&0o022 != 0 {
			return exposureSocketParent
		}
	}
	return ""
}

// groupHasOthers reports whether a group could hold a tenant: any member
// other than root and the rspamd user, or members CSM could not read.
func (f ControllerHostFacts) groupHasOthers(gid int) bool {
	members, ok := f.GroupMembers[gid]
	if !ok {
		return true
	}
	for _, m := range members {
		if m != "root" && m != f.RspamdUser {
			return true
		}
	}
	return false
}
