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

	ports []int
	// listenPorts holds ports named by ListenAddress entries; listenBare
	// records whether any ListenAddress omitted one.
	listenPorts []int
	listenBare  bool
	hasListen   bool
}

// Parse reads path and every file it includes. A missing or unreadable root
// file yields a Config of pure compiled defaults with Present reporting false,
// so callers can tell "sshd runs on defaults" from "there is no sshd config
// here at all".
func Parse(fsys FS, path string) *Config {
	c := &Config{values: make(map[string]string)}
	c.present = c.parseFile(fsys, path, filepath.Dir(path), 0)
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
	ports := append([]int(nil), c.listenPorts...)
	if !c.hasListen || c.listenBare {
		base := c.ports
		if len(base) == 0 {
			base = []int{defaultPort}
		}
		ports = append(ports, base...)
	}
	return sortedUnique(ports)
}

// parseFile reads one config file, following Include directives relative to
// rootDir. It reports whether the file was readable.
func (c *Config) parseFile(fsys FS, path, rootDir string, depth int) bool {
	if depth > maxIncludeDepth {
		return false
	}
	f, err := fsys.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	inMatch := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		keyword, value, ok := splitDirective(line)
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
			for _, pattern := range strings.Fields(value) {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(rootDir, pattern)
				}
				matches, globErr := fsys.Glob(pattern)
				if globErr != nil {
					continue
				}
				for _, m := range matches {
					c.parseFile(fsys, m, rootDir, depth+1)
				}
			}
		case "port":
			if port, valid := parsePort(value); valid {
				c.ports = append(c.ports, port)
			}
		case "listenaddress":
			c.recordListenAddress(value)
		default:
			if _, exists := c.values[keyword]; !exists {
				c.values[keyword] = value
			}
		}
	}
	return true
}

// recordListenAddress notes whether a ListenAddress binds an explicit port.
// Forms without one ("0.0.0.0", "::", "host rdomain N") inherit Port.
func (c *Config) recordListenAddress(value string) {
	c.hasListen = true
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return
	}
	_, portStr, err := net.SplitHostPort(fields[0])
	if err != nil {
		c.listenBare = true
		return
	}
	port, valid := parsePort(portStr)
	if !valid {
		c.listenBare = true
		return
	}
	c.listenPorts = append(c.listenPorts, port)
}

// splitDirective splits "Keyword value", "Keyword=value" and tab-separated
// forms, all of which sshd accepts.
func splitDirective(line string) (keyword, value string, ok bool) {
	sep := strings.IndexFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '='
	})
	if sep <= 0 {
		return "", "", false
	}
	keyword = strings.ToLower(line[:sep])
	value = strings.TrimSpace(strings.TrimLeft(line[sep:], " \t="))
	if value == "" {
		return "", "", false
	}
	return keyword, value, true
}

func parsePort(s string) (int, bool) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
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
