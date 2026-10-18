package antispam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
)

// Bound allocations before decoding the full dump, including unrelated sections.
const maxControllerDumpBytes = 16 << 20

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
	if len(fullDump) > maxControllerDumpBytes {
		return cfg, errors.New("configdump worker controller: dump is too large")
	}
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
		l, bindErr := parseControllerBind(b)
		if bindErr != nil {
			return ControllerConfig{}, bindErr
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
	var one *string
	if err := json.Unmarshal(raw, &one); err == nil && one != nil {
		return []string{*one}, nil
	}
	var many []*string
	if err := json.Unmarshal(raw, &many); err != nil || many == nil {
		return nil, fmt.Errorf("configdump worker controller: %s is not a string or a list of strings", name)
	}
	values := make([]string, 0, len(many))
	for _, value := range many {
		if value == nil {
			return nil, fmt.Errorf("configdump worker controller: %s contains a non-string entry", name)
		}
		values = append(values, *value)
	}
	return values, nil
}

func passwordSet(fields map[string]json.RawMessage, name string) (bool, error) {
	raw, ok := fields[name]
	if !ok {
		return false, nil
	}
	var value *string
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return false, fmt.Errorf("configdump worker controller: %s is not a string", name)
	}
	return *value != "", nil
}

func parseControllerBind(raw string) (ControllerListener, error) {
	l := ControllerListener{Raw: raw}
	for _, c := range raw {
		if c < ' ' || c == 0x7f {
			return ControllerListener{}, errors.New("configdump worker controller: bind_socket contains a control character")
		}
	}
	addr := strings.Trim(raw, " ")
	// TLS does not change the listener address or the controller's auth policy.
	if len(addr) > 4 && strings.EqualFold(addr[len(addr)-4:], " ssl") {
		addr = addr[:len(addr)-4]
	}
	if addr == "" {
		return l, errors.New("configdump worker controller: empty bind_socket entry")
	}
	if strings.HasPrefix(addr, "systemd:") {
		// The dump does not say whether the inherited descriptor is TCP or Unix.
		return ControllerListener{}, errors.New("configdump worker controller: bind_socket systemd endpoint is unresolved")
	}
	if !strings.HasPrefix(addr, "/") {
		if !controllerTCPAddress(addr) {
			return l, errors.New("configdump worker controller: bind_socket entry is neither an absolute Unix path nor host:port")
		}
		l.HostPort = addr
		return l, nil
	}
	// Rspamd separates Unix options with spaces or commas. Cleaning the path
	// would change its target when a component before ".." is a symlink.
	parts := strings.FieldsFunc(addr, func(r rune) bool { return r == ' ' || r == ',' })
	if len(parts[0]) > maxSocketPath {
		return ControllerListener{}, errors.New("configdump worker controller: bind_socket Unix path is too long")
	}
	l.Unix, l.Path = true, parts[0]
	for _, opt := range parts[1:] {
		name, value, ok := strings.Cut(opt, "=")
		if !ok || !strings.EqualFold(name, "mode") {
			continue
		}
		// Rspamd uses strtoul with base 0: only a leading zero means octal.
		base := 10
		if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
			base, value = 16, value[2:]
		} else if strings.HasPrefix(value, "0") {
			base = 8
		}
		mode, err := strconv.ParseUint(value, base, 32)
		if err != nil || mode == 0 || mode > 0o7777 {
			return ControllerListener{}, errors.New("configdump worker controller: bind_socket mode is not a valid file mode")
		}
		l.Mode = fs.FileMode(mode & 0o777)
		if mode&0o4000 != 0 {
			l.Mode |= fs.ModeSetuid
		}
		if mode&0o2000 != 0 {
			l.Mode |= fs.ModeSetgid
		}
		if mode&0o1000 != 0 {
			l.Mode |= fs.ModeSticky
		}
	}
	return l, nil
}

// ControllerHostFacts is what exposure needs beyond the loaded worker:
// host addresses a trust entry could name, the facts of each Unix
// controller socket, and the members of each group that could own one.
type ControllerHostFacts struct {
	// Addrs retains each assigned interface address, not its masked subnet.
	Addrs   []netip.Prefix
	Sockets map[string]SocketFacts
	// GroupMembers includes primary and supplementary members. Omit a group
	// when either inventory is unavailable; an empty list means no members.
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
	// PrefixFrom discards zones, including arbitrary text after '%'. Such
	// an entry is not an unambiguous address in a secure_ip network map.
	if a, err := netip.ParseAddr(entry); err == nil && a.Zone() == "" {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// reachable compares IPv4 addresses in both spellings: netip never matches
// IPv4 against IPv4-mapped IPv6, and a trust entry may use either.
func reachable(p netip.Prefix, hostAddrs []netip.Prefix) bool {
	for _, local := range localPrefixes {
		if p.Overlaps(local) {
			return true
		}
		if local.Addr().Is4() && p.Overlaps(netip.PrefixFrom(netip.AddrFrom16(local.Addr().As16()), local.Bits()+96)) {
			return true
		}
	}
	for _, host := range hostAddrs {
		// A local process can use the assigned address, not every neighbor
		// on its subnet. netip treats IPv4 and mapped IPv6 as separate
		// families, but both spellings identify the same local endpoint.
		a := host.Addr().Unmap()
		if p.Contains(a) || a.Is4() && p.Contains(netip.AddrFrom16(a.As16())) {
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
	if s.Socket.Mode.Type() != fs.ModeSocket || len(s.Parents) == 0 {
		return exposureSocketUnknown
	}
	trusted := func(uid int) bool { return uid == 0 || uid == f.RspamdUID }
	var privateDirs []string
parents:
	for _, p := range s.Parents {
		if !p.Mode.IsDir() {
			return exposureSocketUnknown
		}
		// A private detour still hides its own descendants, even when it
		// does not hide the socket at the end of the resolved path.
		for _, dir := range privateDirs {
			if ancestorOf(dir, p.Path) {
				continue parents
			}
		}
		if !trusted(p.UID) || p.ExtACL {
			return exposureSocketParent
		}
		if !f.othersPermit(p, 0o1) {
			// Only a real ancestor hides the socket. A directory met on a
			// symlink detour does not: the real path stays usable.
			if ancestorOf(p.Path, s.Socket.Path) {
				return ""
			}
			privateDirs = append(privateDirs, p.Path)
			continue
		}
		if f.othersPermit(p, 0o3) {
			if p.Mode&fs.ModeSticky == 0 {
				return exposureSocketParent
			}
			// Sticky directories protect trusted children from replacement.
			// Parents omits symlink ownership, so a redirected walk cannot
			// prove that every child looked up here has a trusted owner.
			if !directSocketPath(l, s) {
				return exposureSocketUnknown
			}
			// The next directory or socket owner is checked below.
		}
	}
	sock := s.Socket
	if !trusted(sock.UID) || sock.ExtACL || f.othersPermit(sock, 0o2) {
		return exposureSocket
	}
	return ""
}

func ancestorOf(dir, p string) bool {
	for parent := filepath.Dir(p); ; parent = filepath.Dir(parent) {
		if parent == dir {
			return true
		}
		if parent == "/" || parent == "." {
			return false
		}
	}
}

func directSocketPath(l ControllerListener, s SocketFacts) bool {
	if l.Path != s.Socket.Path {
		return false
	}
	parent := filepath.Dir(s.Socket.Path)
	for i := len(s.Parents) - 1; i >= 0; i-- {
		if s.Parents[i].Path != parent {
			return false
		}
		parent = filepath.Dir(parent)
	}
	return s.Parents[0].Path == "/"
}

// othersPermit requires all requested bits in the same permission class:
// group write and other search do not combine into directory access.
func (f ControllerHostFacts) othersPermit(p PathFacts, want fs.FileMode) bool {
	perm := p.Mode.Perm()
	return perm&want == want || perm>>3&want == want && f.groupHasOthers(p.GID)
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

// Validate syntax without resolving hostnames or opening sockets. Rspamd permits
// omitted ports and an optional numeric priority after an explicit port.
func controllerTCPAddress(addr string) bool {
	var host, suffix string
	if strings.HasPrefix(addr, "[") {
		var ok bool
		host, suffix, ok = strings.Cut(addr[1:], "]")
		ip, err := netip.ParseAddr(host)
		if !ok || err != nil || !ip.Is6() {
			return false
		}
	} else {
		host, suffix, _ = strings.Cut(addr, ":")
		if len(host) != len(addr) {
			suffix = ":" + suffix
		}
		switch strings.ToLower(host) {
		case "*", "*v4", "*v6":
		default:
			if host == "" || strings.HasPrefix(host, ".") {
				return false
			}
			for _, c := range host {
				switch {
				case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
				default:
					return false
				}
			}
		}
	}
	if suffix == "" {
		return true
	}
	if !strings.HasPrefix(suffix, ":") {
		return false
	}
	port, priority, hasPriority := strings.Cut(suffix[1:], ":")
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return false
	}
	if hasPriority {
		if _, err := strconv.ParseUint(priority, 10, 32); err != nil {
			return false
		}
	}
	return true
}
