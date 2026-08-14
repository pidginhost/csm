// Package sshdconf reads the effective sshd_config the way sshd itself does:
// Include directives are followed, Match blocks are ignored because their
// directives are connection-scoped, and most keywords keep first-match-wins
// semantics.
//
// Port is the exception. sshd accumulates every Port directive, so a config
// can name several listening ports; collapsing them into a single value hides
// ports and makes any firewall guard built on top of it wrong.
package sshdconf

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// DefaultPath is where sshd reads its configuration from.
const DefaultPath = "/etc/ssh/sshd_config"

// defaultPort is OpenSSH's compiled-in listen port, used when nothing in the
// config names one.
const defaultPort = 22

// maxIncludeDepth mirrors OpenSSH's own nesting limit. Without it a config
// that includes itself recurses until the stack overflows, which Go cannot
// recover from.
const maxIncludeDepth = 16

// compiledDefaults are the OpenSSH defaults for the keywords CSM reads.
var compiledDefaults = map[string]string{
	"addressfamily":          "any",
	"protocol":               "2",
	"passwordauthentication": "yes",
	"permitrootlogin":        "prohibit-password",
	"maxauthtries":           "6",
	"x11forwarding":          "no",
	"usedns":                 "no",
}

// FS is the file access parsing needs. It matches the corresponding subset of
// the internal/checks OS injector, so that package can pass its own hook and
// keep its tests fake-driven.
type FS interface {
	Open(name string) (*os.File, error)
	Glob(pattern string) ([]string, error)
}

// OSFS reads the real filesystem.
type OSFS struct{}

// #nosec G304 -- callers pass the operator-owned sshd config path.
func (OSFS) Open(name string) (*os.File, error) { return os.Open(name) }

// Glob expands an Include pattern.
func (OSFS) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

// Config is a parsed sshd_config.
type Config struct {
	present bool
	values  map[string]string

	ports           []int
	listenAddresses []listenAddress
}

type listenAddress struct {
	host string
	port int
}

// Parse reads path and every file it includes. A missing or unreadable root
// file yields a Config of pure compiled defaults with Present reporting false,
// so callers can tell "sshd runs on defaults" from "there is no sshd config
// here at all".
func Parse(fsys FS, path string) *Config {
	c := &Config{values: make(map[string]string)}
	c.present = c.parseFile(fsys, path, filepath.Dir(path), 0, make(map[string]struct{}))
	return c
}

// Present reports whether the root config file was readable.
func (c *Config) Present() bool { return c.present }

// Value returns the effective value of keyword, lowercased, falling back to
// the OpenSSH compiled default. Keywords with no shipped default return "".
func (c *Config) Value(keyword string) string {
	key := strings.ToLower(keyword)
	if v, ok := c.values[key]; ok {
		return strings.ToLower(v)
	}
	return compiledDefaults[key]
}

// ListenPorts returns the sorted TCP ports sshd accepts connections on.
//
// Port applies only to ListenAddress entries that omit a port, so a config
// where every ListenAddress carries its own port never binds the Port value.
func (c *Config) ListenPorts() []int {
	v4, v6 := c.listenPorts(false)
	return sortedUnique(append(v4, v6...))
}

// RemoteListenPorts returns the IPv4 and IPv6 ports reachable beyond the
// local host. It honors AddressFamily and explicit ListenAddress directives,
// and excludes loopback-only listeners that an inbound firewall cannot cut
// off.
func (c *Config) RemoteListenPorts() (ipv4, ipv6 []int) {
	return c.listenPorts(true)
}

// parseFile reads one config file, following Include directives relative to
// rootDir. It reports whether the file was readable.
func (c *Config) parseFile(fsys FS, path, rootDir string, depth int, seen map[string]struct{}) bool {
	if depth > maxIncludeDepth {
		return false
	}
	path = filepath.Clean(path)
	// A glob may match its containing file, and mutually recursive globs can
	// branch exponentially before the depth limit. Re-reading a file cannot
	// change this parser's first-value or set-like accumulated results.
	if _, parsed := seen[path]; parsed {
		return false
	}
	seen[path] = struct{}{}

	f, err := fsys.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	inMatch := false
	reader := bufio.NewReader(f)
	for {
		rawLine, readErr := reader.ReadString('\n')
		if len(rawLine) == 0 && readErr != nil {
			break
		}
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		keyword, args, ok := splitDirective(line)
		if !ok {
			continue
		}

		// A Match block runs to the next Match keyword or EOF regardless of
		// indentation, per sshd_config(5). Everything inside it is
		// connection-scoped, so the global view skips it -- including any
		// Include, whose contents would also be Match-scoped.
		if keyword == "match" {
			inMatch = true
			continue
		}
		if inMatch {
			continue
		}

		switch keyword {
		case "include":
			// sshd resolves a relative Include against its config directory,
			// not against the including file, so nested drop-ins agree with
			// the top-level file.
			for _, pattern := range args {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(rootDir, pattern)
				}
				matches, globErr := fsys.Glob(pattern)
				if globErr != nil {
					continue
				}
				for _, m := range matches {
					c.parseFile(fsys, m, rootDir, depth+1, seen)
				}
			}
		case "port":
			if port, valid := parsePort(args[0]); valid {
				c.ports = append(c.ports, port)
			}
		case "listenaddress":
			c.recordListenAddress(args[0])
		default:
			if _, exists := c.values[keyword]; !exists {
				c.values[keyword] = args[0]
			}
		}
	}
	return true
}

// recordListenAddress records an address and its optional explicit port.
// Forms without a port inherit every Port directive.
func (c *Config) recordListenAddress(value string) {
	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		c.listenAddresses = append(c.listenAddresses, listenAddress{host: strings.Trim(value, "[]")})
		return
	}
	port, valid := parsePort(portStr)
	if !valid {
		c.listenAddresses = append(c.listenAddresses, listenAddress{host: host})
		return
	}
	c.listenAddresses = append(c.listenAddresses, listenAddress{host: host, port: port})
}

// splitDirective splits a keyword from its OpenSSH-style argument vector.
// Quoting, basic escapes, and comments follow argv_split in OpenSSH.
func splitDirective(line string) (keyword string, args []string, ok bool) {
	sep := strings.IndexFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '='
	})
	if sep <= 0 {
		return "", nil, false
	}
	keyword = strings.ToLower(line[:sep])
	rest := strings.TrimLeft(line[sep:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	args, ok = splitArguments(rest)
	if !ok || len(args) == 0 {
		return "", nil, false
	}
	return keyword, args, true
}

func splitArguments(s string) ([]string, bool) {
	var args []string
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i == len(s) || s[i] == '#' {
			break
		}

		var arg strings.Builder
		var quote byte
		for i < len(s) {
			ch := s[i]
			switch {
			case ch == '\\' && i+1 < len(s) &&
				(s[i+1] == '\'' || s[i+1] == '"' || s[i+1] == '\\' || (quote == 0 && s[i+1] == ' ')):
				i++
				arg.WriteByte(s[i])
			case quote == 0 && (ch == ' ' || ch == '\t'):
				i++
				goto argumentDone
			case quote == 0 && (ch == '\'' || ch == '"'):
				quote = ch
			case quote != 0 && ch == quote:
				quote = 0
			default:
				arg.WriteByte(ch)
			}
			i++
		}

	argumentDone:
		if quote != 0 {
			return nil, false
		}
		args = append(args, arg.String())
	}
	return args, true
}

func parsePort(s string) (int, bool) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err == nil {
		return port, port >= 1 && port <= 65535
	}
	port, err = net.LookupPort("tcp", s)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

func (c *Config) listenPorts(remoteOnly bool) (ipv4, ipv6 []int) {
	base := c.ports
	if len(base) == 0 {
		base = []int{defaultPort}
	}
	allowV4 := c.Value("addressfamily") != "inet6"
	allowV6 := c.Value("addressfamily") != "inet"

	if len(c.listenAddresses) == 0 {
		if allowV4 {
			ipv4 = append(ipv4, base...)
		}
		if allowV6 {
			ipv6 = append(ipv6, base...)
		}
		return sortedUnique(ipv4), sortedUnique(ipv6)
	}

	for _, listener := range c.listenAddresses {
		isV4, isV6, loopback := addressFamilies(listener.host)
		if remoteOnly && loopback {
			continue
		}
		ports := base
		if listener.port != 0 {
			ports = []int{listener.port}
		}
		if allowV4 && isV4 {
			ipv4 = append(ipv4, ports...)
		}
		if allowV6 && isV6 {
			ipv6 = append(ipv6, ports...)
		}
	}
	return sortedUnique(ipv4), sortedUnique(ipv6)
}

func addressFamilies(host string) (ipv4, ipv6, loopback bool) {
	if host == "*" {
		return true, true, false
	}
	canonicalHost := strings.TrimSuffix(strings.ToLower(host), ".")
	if canonicalHost == "localhost" || strings.HasSuffix(canonicalHost, ".localhost") {
		return true, true, true
	}
	if zone := strings.LastIndex(host, "%"); zone >= 0 {
		host = host[:zone]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true, true, false
	}
	if ip.To4() != nil {
		return true, false, ip.IsLoopback()
	}
	return false, true, ip.IsLoopback()
}

func sortedUnique(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
