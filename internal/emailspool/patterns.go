package emailspool

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Policies is the loaded contents of policies/email/*.yaml. Used by Stage 1
// (mailer classes, http_proxy_ranges) and Stage 2 (policy_blocks). Each
// data file has its own schema; failing to parse one file does not abort
// the whole load -- each category degrades independently.
type Policies struct {
	mu             sync.RWMutex
	suspiciousMail []string
	safeMail       []string
	proxyNets      []*net.IPNet
	// selfIPs are the host's own interface addresses. PHP-relay Path 4
	// (HTTP-IP fanout) treats them as proxy-equivalent so WordPress cron
	// and any other local loopback-to-public traffic does not page on
	// "one IP triggered N scripts". Populated by RefreshSelfIPs.
	selfIPs []net.IP
}

// hostIPsFunc returns the set of non-loopback host IPs to treat as self.
// Package-level so tests can inject deterministic addresses.
var hostIPsFunc = enumerateHostIPs

// enumerateHostIPs reads every IPv4/IPv6 address bound to a non-loopback
// interface. Errors from net.InterfaceAddrs (extremely rare; only on syscall
// failure) drop us to an empty list; loopback fallback in IsProxyIP still
// covers 127/8 and ::1.
func enumerateHostIPs() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// RefreshSelfIPs re-enumerates host addresses and replaces the cached set.
// Safe to call concurrently with IsProxyIP. LoadPolicies / Reload call this
// automatically so SIGHUP picks up cPanel alias IP additions without code
// changes to callers; exposed for tests and the daemon Flow E ticker.
func (p *Policies) RefreshSelfIPs() {
	ips := hostIPsFunc()
	p.mu.Lock()
	p.selfIPs = ips
	p.mu.Unlock()
}

type mailerClassesYAML struct {
	Version    int      `yaml:"version"`
	Suspicious []string `yaml:"suspicious"`
	Safe       []string `yaml:"safe"`
}

//nolint:unused // consumed by E2/E3
type httpProxyRangesYAML struct {
	Version int      `yaml:"version"`
	CIDRs   []string `yaml:"cidrs"`
}

// LoadPolicies reads all known policy files in dir. Missing files are
// treated as "no entries"; corrupt files return an error per file but do
// not abort the load. The returned Policies is safe for concurrent use.
func LoadPolicies(dir string) (*Policies, error) {
	p := &Policies{}
	if err := p.load(dir); err != nil {
		return p, err
	}
	return p, nil
}

func (p *Policies) load(dir string) error {
	p.mu.Lock()
	// Refresh self IPs alongside file-backed policies so SIGHUP picks up
	// any cPanel alias IP additions that landed since startup.
	p.selfIPs = hostIPsFunc()
	defer p.mu.Unlock()

	var firstErr error
	setErr := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	// mailer_classes.yaml
	// #nosec G304 -- dir is the operator-supplied policy directory; filename is a fixed literal under it.
	if data, err := os.ReadFile(filepath.Join(dir, "mailer_classes.yaml")); err == nil {
		var raw mailerClassesYAML
		if uerr := yaml.Unmarshal(data, &raw); uerr != nil {
			setErr(fmt.Errorf("parse mailer_classes.yaml: %w", uerr))
		} else {
			p.suspiciousMail = lowerList(raw.Suspicious)
			p.safeMail = lowerList(raw.Safe)
		}
	} else if !os.IsNotExist(err) {
		setErr(fmt.Errorf("read mailer_classes.yaml: %w", err))
	}

	// http_proxy_ranges.yaml
	// #nosec G304 -- dir is the operator-supplied policy directory; filename is a fixed literal under it.
	if data, err := os.ReadFile(filepath.Join(dir, "http_proxy_ranges.yaml")); err == nil {
		var raw httpProxyRangesYAML
		if uerr := yaml.Unmarshal(data, &raw); uerr != nil {
			setErr(fmt.Errorf("parse http_proxy_ranges.yaml: %w", uerr))
		} else {
			nets := make([]*net.IPNet, 0, len(raw.CIDRs))
			for _, c := range raw.CIDRs {
				_, n, perr := net.ParseCIDR(strings.TrimSpace(c))
				if perr != nil {
					setErr(fmt.Errorf("invalid CIDR %q in http_proxy_ranges.yaml: %w", c, perr))
					continue
				}
				nets = append(nets, n)
			}
			p.proxyNets = nets
		}
	} else if !os.IsNotExist(err) {
		setErr(fmt.Errorf("read http_proxy_ranges.yaml: %w", err))
	}

	return firstErr
}

// Reload refreshes from dir while keeping previous values for any category
// whose new file is corrupt (existing reload-error contract). Used by SIGHUP.
//
//nolint:unused // consumed by E3
func (p *Policies) Reload(dir string) error {
	return p.load(dir)
}

// MailerSuspicious reports whether x-mailer header matches any suspicious
// substring. Substrings, not exact match.
func (p *Policies) MailerSuspicious(xMailer string) bool {
	if xMailer == "" {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	low := strings.ToLower(xMailer)
	for _, s := range p.suspiciousMail {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

// MailerSafe reports whether x-mailer matches any safe substring.
func (p *Policies) MailerSafe(xMailer string) bool {
	if xMailer == "" {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	low := strings.ToLower(xMailer)
	for _, s := range p.safeMail {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

// IsProxyIP reports whether ip falls within any configured CDN/proxy CIDR,
// is one of the host's own interface addresses, or is a loopback address.
// Used by Path 4 to skip fanout counting for IPs that are CDN front IPs,
// the local host (WordPress cron, panel-internal callbacks), or 127/::1.
func (p *Policies) IsProxyIP(ip string) bool {
	if ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() {
		return true
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, n := range p.proxyNets {
		if n.Contains(parsed) {
			return true
		}
	}
	for _, self := range p.selfIPs {
		if self.Equal(parsed) {
			return true
		}
	}
	return false
}

func lowerList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
