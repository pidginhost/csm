package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// outboundDependency is one TCP destination the daemon dials because the
// operator enabled the feature that needs it. what reads as a clause the
// warning can quote, e.g. "alerts.webhook.url dials panel.example.com on
// TCP port 8443".
type outboundDependency struct {
	what string
	host string // hostname or literal IP; empty when the endpoints are vendor-fixed
	port int
}

// builtInHTTPSEndpoints names the outbound HTTPS destinations that are not
// configurable: threat feeds, AbuseIPDB, MaxMind, YARA Forge, AI-crawler
// range feeds and the release check. They share one warning because dropping
// 443 from tcp_out silences all of them at once.
const builtInHTTPSEndpoints = "built-in HTTPS endpoints (threat feeds, signature, GeoIP and bot-range updates, AbuseIPDB, release check)"

// outboundDependencies lists every TCP destination the daemon will dial with
// the features currently enabled. Loopback destinations are left out because
// the output chain accepts loopback ahead of any port rule.
func outboundDependencies(cfg *Config) []outboundDependency {
	deps := []outboundDependency{{
		what: builtInHTTPSEndpoints + " need TCP port 443 outbound",
		port: 443,
	}}
	add := func(label, host string, port int) {
		if isLoopbackHost(host) {
			return
		}
		deps = append(deps, outboundDependency{
			what: fmt.Sprintf("%s dials %s on TCP port %d", label, host, port),
			host: host,
			port: port,
		})
	}
	addURL := func(label, raw string) {
		if host, port, ok := urlDialTarget(raw); ok {
			add(label, host, port)
		}
	}
	addHostPort := func(label, raw string) {
		if host, port, ok := hostPortDialTarget(raw); ok {
			add(label, host, port)
		}
	}

	if cfg.Alerts.Email.Enabled && cfg.Alerts.Email.SMTP != "" {
		addHostPort("alerts.email.smtp", cfg.Alerts.Email.SMTP)
	}
	if cfg.Alerts.Webhook.Enabled && cfg.Alerts.Webhook.URL != "" {
		addURL("alerts.webhook.url", cfg.Alerts.Webhook.URL)
	}
	if cfg.Alerts.Heartbeat.Enabled && cfg.Alerts.Heartbeat.URL != "" {
		addURL("alerts.heartbeat.url", cfg.Alerts.Heartbeat.URL)
	}
	syslog := cfg.Alerts.AuditLog.Syslog
	if syslog.Enabled && (syslog.Network == "tcp" || syslog.Network == "tls") {
		addHostPort("alerts.audit_log.syslog.address", syslog.Address)
	}
	if cfg.AutoResponse.VerdictCallback.Enabled && cfg.AutoResponse.VerdictCallback.URL != "" {
		addURL("auto_response.verdict_callback.url", cfg.AutoResponse.VerdictCallback.URL)
	}
	if cfg.Reputation.Rspamd.Enabled && cfg.Reputation.Rspamd.URL != "" {
		addURL("reputation.rspamd.url", cfg.Reputation.Rspamd.URL)
	}
	if cfg.Reputation.Upstream.Enabled && cfg.Reputation.Upstream.URL != "" {
		addURL("reputation.upstream.url", cfg.Reputation.Upstream.URL)
	}
	if cfg.Reputation.Report.Enabled {
		for i, target := range cfg.Reputation.Report.Targets {
			addURL(fmt.Sprintf("reputation.report.targets[%d].url", i), target.URL)
		}
	}
	if cfg.Reputation.Central.Enabled && cfg.Reputation.Central.SetURL != "" {
		addURL("reputation.central.set_url", cfg.Reputation.Central.SetURL)
	}
	// The signature updater runs whenever an update URL is set.
	if cfg.Signatures.UpdateURL != "" {
		addURL("signatures.update_url", cfg.Signatures.UpdateURL)
	}
	if cfg.Signatures.YaraForge.Enabled && cfg.Signatures.YaraForge.DownloadURL != "" {
		addURL("signatures.yara_forge.download_url", cfg.Signatures.YaraForge.DownloadURL)
	}
	if cfg.Sentry.Enabled && cfg.Sentry.DSN != "" {
		addURL("sentry.dsn", cfg.Sentry.DSN)
	}
	if cfg.UpdatesCheckEnabled() && cfg.Updates.GitHubAPIURL != "" {
		addURL("updates.github_api_url", cfg.Updates.GitHubAPIURL)
	}
	return deps
}

// urlDialTarget resolves the host and port a URL is dialed on the way the
// HTTP client does: an explicit port wins, otherwise the scheme default. A
// URL that yields no port is left to the URL validators.
func urlDialTarget(raw string) (host string, port int, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", 0, false
	}
	host = u.Hostname()
	if host == "" {
		return "", 0, false
	}
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, false
		}
		return host, port, true
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return host, 443, true
	case "http":
		return host, 80, true
	}
	return "", 0, false
}

// hostPortDialTarget splits a host:port dial address. Addresses without a
// port cannot be dialed at all and are left to the field's own validator.
func hostPortDialTarget(raw string) (host string, port int, ok bool) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil || host == "" {
		return "", 0, false
	}
	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

// firewallEgressResults warns when the enabled firewall's outbound policy
// would refuse a connection the daemon itself needs. The output chain is
// default-drop and ends in a TCP reset, so the failure reads as the far end
// being down while the host looks healthy locally. Like the inbound checks
// these are warnings, never errors: an operator may route through a proxy
// that validation cannot see.
//
// Coverage is limited to what the daemon dials from its own config plus the
// ports declared under firewall.required_tcp_out. A third-party agent's
// egress is only checked when it declares its ports there.
func firewallEgressResults(cfg *Config) []ValidationResult {
	fw := cfg.Firewall
	if fw == nil || !fw.Enabled {
		return nil
	}

	// Mirror the engine: the output chain is accept-all unless some outbound
	// list is set; IPv4 is accepted wholesale when only IPv6 lists are set;
	// IPv6 is accepted wholesale unless it is managed.
	tcp6Out := fw.TCP6Out
	if len(tcp6Out) == 0 {
		tcp6Out = fw.TCPOut
	}
	udp6Out := fw.UDP6Out
	if len(udp6Out) == 0 {
		udp6Out = fw.UDPOut
	}
	ipv4Filtered := len(fw.TCPOut) > 0 || len(fw.UDPOut) > 0
	ipv6Filtered := fw.IPv6 && (ipv4Filtered || len(tcp6Out) > 0 || len(udp6Out) > 0)
	if !ipv4Filtered && !ipv6Filtered {
		return nil
	}

	// smtp_block installs per-UID accepts for the mail ports ahead of the
	// port rules, and the daemon runs as root, which is always on that list.
	rootMailPort := func(port int) bool {
		return fw.SMTPBlock && containsPort(fw.SMTPPorts, port)
	}
	allowed4 := func(port int) bool { return containsPort(fw.TCPOut, port) || rootMailPort(port) }
	allowed6 := func(port int) bool { return containsPort(tcp6Out, port) || rootMailPort(port) }

	deps := outboundDependencies(cfg)
	for _, port := range fw.RequiredTCPOut {
		if port < 1 || port > 65535 {
			continue // reported as an error by firewallValueResults
		}
		deps = append(deps, outboundDependency{
			what: fmt.Sprintf("firewall.required_tcp_out declares TCP port %d", port),
			port: port,
		})
	}

	var results []ValidationResult
	for _, dep := range deps {
		wantV4, wantV6 := dialFamilies(dep.host)
		if wantV4 && ipv4Filtered && !allowed4(dep.port) {
			results = append(results, ValidationResult{"warn", "firewall.tcp_out",
				fmt.Sprintf("%s but tcp_out does not allow it; once the firewall applies, connections to that port are refused", dep.what)})
		}
		// An inherited tcp6_out is the same list as tcp_out, so the IPv4
		// warning above already covers a hostname that may resolve either
		// way. Only an explicit tcp6_out, or a literal IPv6 destination
		// that never dials over IPv4, needs its own line.
		if wantV6 && ipv6Filtered && !allowed6(dep.port) && (len(fw.TCP6Out) > 0 || !wantV4) {
			results = append(results, ValidationResult{"warn", "firewall.tcp6_out",
				fmt.Sprintf("IPv6 is managed and tcp6_out does not allow it: %s", dep.what)})
		}
	}
	return results
}

// dialFamilies reports which IP families a destination can be dialed over. A
// literal address pins one family; a hostname (or the vendor endpoints, which
// have no single host) may resolve to either.
func dialFamilies(host string) (ipv4, ipv6 bool) {
	ip := net.ParseIP(host)
	if ip == nil {
		return true, true
	}
	if ip.To4() != nil {
		return true, false
	}
	return false, true
}
