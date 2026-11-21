package checks

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/pidginhost/csm/internal/netutil"
	"github.com/pidginhost/csm/internal/platform"
)

// RewriteState says whether the web server may replace the connecting
// address it logs.
type RewriteState uint8

const (
	// RewriteUnknown: not detected yet, or the configuration could not be
	// read completely. Admission treats it as rewritten.
	RewriteUnknown RewriteState = iota
	// RewriteNone: the web logs record the connecting address.
	RewriteNone
	// RewriteActive: the web logs may record an address from a request
	// header or PROXY protocol; this build reads no separate peer field.
	RewriteActive
)

// HTTPRewrite is what the host's web server does to the address it logs.
// Directive and File name the first setting that rewrites; Reason says why
// the state is unknown.
type HTTPRewrite struct {
	State     RewriteState
	Server    platform.WebServer
	Directive string
	File      string
	Reason    string
	// Format marks an active rewrite found in a log format that writes
	// request data where CSM reads the client: any client chooses it.
	Format bool
	// RealIP is nginx's realip setup when the active rewrite is nginx's own
	// and its configuration was read completely; nil otherwise.
	RealIP *NginxRealIP
	// ProxyProtocol marks nginx that may take client addresses from PROXY
	// protocol: a proxy_protocol real_ip_header in any context, or
	// set_real_ip_from in a tree CSM could not read whole.
	ProxyProtocol bool
	// BufferedLogs marks Apache that may hold log lines in per-process
	// buffers (BufferedLogs On, or a tree CSM could not read whole): its
	// peer log can lag its access logs without bound.
	BufferedLogs bool
}

// NginxRealIP is every real_ip_header and set_real_ip_from value in an nginx
// configuration tree with an explicit HTTP-level header and valid contexts.
type NginxRealIP struct {
	Headers []string
	From    []string
}

func (s RewriteState) String() string {
	switch s {
	case RewriteNone:
		return "none"
	case RewriteActive:
		return "active"
	}
	return "unknown"
}

// httpRewrite is the state the daemon last read; nil until it reads one.
var httpRewrite atomic.Pointer[HTTPRewrite]

// SetHTTPRewrite publishes the web server state admission reads.
func SetHTTPRewrite(r HTTPRewrite) {
	r = cloneHTTPRewrite(r)
	httpRewrite.Store(&r)
}

// CurrentHTTPRewrite is the published state, unknown before the first.
func CurrentHTTPRewrite() HTTPRewrite {
	if r := httpRewrite.Load(); r != nil {
		return cloneHTTPRewrite(*r)
	}
	return HTTPRewrite{}
}

// Equal compares detected settings rather than the storage of their snapshots.
func (r HTTPRewrite) Equal(other HTTPRewrite) bool {
	a, b := r.RealIP, other.RealIP
	r.RealIP, other.RealIP = nil, nil
	if r != other {
		return false
	}
	if a == nil || b == nil {
		return a == b
	}
	return slices.Equal(a.Headers, b.Headers) && slices.Equal(a.From, b.From)
}

// Callers must not be able to change trust data already published to admission.
func cloneHTTPRewrite(r HTTPRewrite) HTTPRewrite {
	if r.RealIP != nil {
		r.RealIP = &NginxRealIP{Headers: slices.Clone(r.RealIP.Headers), From: slices.Clone(r.RealIP.From)}
	}
	return r
}

// lswsConfigPath is LiteSpeed's own server configuration.
const lswsConfigPath = platform.LiteSpeedConfigPath

// rewriteSources names the files a web server reads. apacheRequired marks
// a server that always loads an Apache tree, so a missing one is unknown.
type rewriteSources struct {
	server         platform.WebServer
	apacheConfig   string
	apacheRequired bool
	nginxConfig    string
	lswsConfig     string
}

// DetectHTTPRewrite reads the host web server's configuration from disk: an
// Apache RemoteIPHeader or RemoteIPProxyProtocol, mod_cloudflare or
// mod_rpaf, an nginx set_real_ip_from, or LiteSpeed's client IP from
// header, in any scope, or a log format that writes a request value where
// CSM reads the client. Apache and nginx formats take precedence because
// their refusals must not fall back to legacy blocking.
func DetectHTTPRewrite(info platform.Info) HTTPRewrite {
	src := rewriteSources{server: info.WebServer}
	switch info.WebServer {
	case platform.WSApache:
		src.apacheConfig, src.apacheRequired = findWebServerConfigPath(info), true
	case platform.WSLiteSpeed:
		// cPanel LiteSpeed also applies the Apache tree it loads.
		src.lswsConfig = lswsConfigPath
		if info.IsCPanel() {
			src.apacheConfig, src.apacheRequired = findWebServerConfigPath(info), true
		}
	case platform.WSNginx:
		src.nginxConfig = joinWebConfigPath(info.NginxConfigRoot(), "nginx.conf")
	}
	return detectHTTPRewrite(src)
}

func detectHTTPRewrite(src rewriteSources) HTTPRewrite {
	r := HTTPRewrite{Server: src.server}
	if src.server == platform.WSApache && src.apacheConfig != "" {
		r.BufferedLogs = apacheBufferedLogs(src.apacheConfig)
	}
	switch src.server {
	case platform.WSNone:
		r.State = RewriteNone
		return r
	case platform.WSApache, platform.WSLiteSpeed, platform.WSNginx:
	default:
		r.Reason = fmt.Sprintf("web server %q is not one CSM reads", src.server)
		return r
	}
	unknown := ""
	if src.lswsConfig != "" {
		directive, err := lswsClientAddressRewrite(src.lswsConfig)
		switch {
		case directive != "":
			r.State, r.Directive, r.File, r.Format = RewriteActive, directive, src.lswsConfig, formatDirective(directive)
			return r
		case err != nil:
			unknown = err.Error()
		}
	}
	if src.apacheConfig != "" {
		directive, file, complete := apacheClientAddressRewrite(src.apacheConfig, src.server == platform.WSLiteSpeed)
		if directive != "" {
			r.State, r.Directive, r.File, r.Format = RewriteActive, directive, file, formatDirective(directive)
			return r
		}
		if !complete && unknown == "" {
			unknown = "the Apache configuration " + src.apacheConfig + " could not be read completely"
		}
	} else if src.apacheRequired && unknown == "" {
		unknown = "no Apache configuration file was found"
	}
	if src.nginxConfig != "" {
		directive, file, complete, realIP, proxyProtocol := nginxClientAddressRewrite(src.nginxConfig)
		if directive != "" {
			r.State, r.Directive, r.File, r.Format = RewriteActive, directive, file, formatDirective(directive)
			if !r.Format && complete && realIP != nil && src.server == platform.WSNginx {
				r.RealIP = realIP
			}
			r.ProxyProtocol = src.server == platform.WSNginx && (proxyProtocol || !complete)
			return r
		}
		if !complete {
			unknown = "the nginx configuration " + src.nginxConfig + " could not be read completely"
		}
	}
	if unknown != "" {
		r.Reason = unknown
		return r
	}
	r.State = RewriteNone
	return r
}

// apacheBufferedLogs reports BufferedLogs set to anything but Off, or an
// Apache tree that could not be read whole.
func apacheBufferedLogs(path string) bool {
	lines, complete := assembleApacheConfigWithStatus(path)
	buffered := false
	valid := walkApacheLines(lines, func(_ apacheConfigLine, fields []string, _ apacheLineContext) {
		if len(fields) > 0 && strings.EqualFold(fields[0], "BufferedLogs") && (len(fields) != 2 || !strings.EqualFold(fields[1], "off")) {
			buffered = true
		}
	})
	return buffered || !complete || !valid
}

// formatDirective reports whether an active rewrite's directive is a log
// format or a log using one, rather than the server's own proxy-header
// handling. These are the only format directives the detectors return.
func formatDirective(directive string) bool {
	name, _, _ := strings.Cut(directive, " ")
	switch strings.ToLower(name) {
	case "logformat", "customlog", "globallog", "transferlog", "errorlogformat", "log_format", "access_log":
		return true
	}
	return false
}

// apacheClientAddressRewrite returns the first directive that replaces the
// client address, its file, and whether the whole tree was read: a
// mod_remoteip header or PROXY protocol, a loaded or configured
// mod_cloudflare, or an enabled mod_rpaf (0.6 or 0.8 names). A log format
// that writes a request value where CSM reads the client takes precedence.
// A rewrite or format directive Apache would refuse leaves the tree unknown.
func apacheClientAddressRewrite(path string, liteSpeed bool) (directive, file string, complete bool) {
	lines, complete := assembleApacheConfigWithStatus(path)
	malformed := false
	logs := apacheLogFormats{liteSpeed: liteSpeed}
	valid := walkApacheLines(lines, func(line apacheConfigLine, fields []string, ctx apacheLineContext) {
		fields, resolved := apacheMacroFields(fields, ctx)
		if !resolved {
			// A macro parameter can name any directive.
			malformed = true
			return
		}
		logs.add(line, fields, ctx)
		if directive != "" {
			return
		}
		is := func(names ...string) bool {
			for _, n := range names {
				if strings.EqualFold(fields[0], n) {
					return true
				}
			}
			return false
		}
		switch {
		case is("RemoteIPHeader", "CloudFlareRemoteIPHeader"):
			if len(fields) != 2 || is("CloudFlareRemoteIPHeader") && fields[1] == "" {
				malformed = true
				return
			}
			directive, file = strings.Join(fields, " "), line.File
		case is("CloudFlareRemoteIPTrustedProxy"):
			if len(fields) < 2 || fields[1] == "" {
				malformed = true
				return
			}
			for _, proxy := range fields[1:] {
				// Apache's ITERATE handler stops at an empty quoted argument.
				if proxy == "" {
					break
				}
				if !apacheCloudflareProxyKnown(proxy) {
					malformed = true
					return
				}
			}
			directive, file = strings.Join(fields, " "), line.File
		case is("DenyAllButCloudFlare"):
			if len(fields) != 1 {
				malformed = true
				return
			}
			// This also implies mod_cloudflare's default address rewrite.
			directive, file = strings.Join(fields, " "), line.File
		case is("LoadModule"):
			// Only Apache can resolve its Define and environment values.
			if len(fields) != 3 || fields[1] == "" || fields[2] == "" || apacheArgumentHasVariable(fields[1]) {
				malformed = true
				return
			}
			if fields[1] == "cloudflare_module" {
				// mod_cloudflare trusts its built-in Cloudflare ranges once loaded.
				directive, file = strings.Join(fields, " "), line.File
			}
		case is("RemoteIPProxyProtocol", "RPAF_Enable", "RPAFenable"):
			switch {
			case len(fields) == 2 && strings.EqualFold(fields[1], "On"):
				directive, file = strings.Join(fields, " "), line.File
			case len(fields) != 2 || !strings.EqualFold(fields[1], "Off"):
				malformed = true
			}
		}
	})
	if f := logs.clientValue(); f != nil {
		directive, file = f.directive, f.file
	}
	return directive, file, complete && valid && !malformed && !logs.malformed
}

// apacheCloudflareProxyKnown follows APR's numeric subnet syntax. Hostnames
// and variables need Apache's own resolution, so cannot prove a valid setting.
func apacheCloudflareProxyKnown(value string) bool {
	ip, mask, hasMask := strings.Cut(value, "/")
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		// APR also accepts one to four decimal octets, with an optional final
		// dot, as an implicit IPv4 network, but only without an explicit mask.
		if hasMask || ip == "" || len(ip) > len("255.255.255.255") || strings.Trim(ip, "0123456789.") != "" {
			return false
		}
		octets := strings.Split(strings.TrimSuffix(ip, "."), ".")
		if len(octets) > 4 {
			return false
		}
		for _, octet := range octets {
			n, parseErr := strconv.Atoi(octet)
			if parseErr != nil || n > 255 {
				return false
			}
		}
		return true
	}
	if addr.Is4In6() || addr.Zone() != "" {
		return false
	}
	if !hasMask {
		return true
	}
	// APR uses strtol for prefix lengths and accepts a dotted IPv4 mask,
	// including non-contiguous masks. A zero prefix length is rejected.
	bits, err := strconv.Atoi(strings.TrimLeft(mask, " \t\r\n\v\f"))
	if err == nil && bits > 0 && bits <= addr.BitLen() {
		return true
	}
	netmask, err := netip.ParseAddr(mask)
	return err == nil && addr.Is4() && netmask.Is4()
}

// nginxClientAddressRewrite returns the first set_real_ip_from, which
// turns on nginx's realip rewrite from real_ip_header or its X-Real-IP
// default. The first log_format an access_log writes that logs a request
// value where CSM reads the client takes precedence. It also returns the
// file and whether the tree and its format framing could be read. HTTP
// and stream have separate namespaces; only HTTP has built-in combined.
func nginxClientAddressRewrite(path string) (directive, file string, complete bool, realIP *NginxRealIP, proxyProtocol bool) {
	directives, complete := nginxDirectives(path)
	realIP = &NginxRealIP{}
	httpHeader := false
	type format struct {
		directive nginxDirective
		value     bool
	}
	type key struct{ module, name string }
	formats := map[key]format{{"http", "combined"}: {}}
	seen := make(map[key]bool)
	var used []format
	// Optional modules can leave their variable names available for user
	// definitions. A familiar spelling alone does not prove a peer value.
	custom := make(map[string]map[string]bool)
	for _, d := range directives {
		if nginxDataContext(d.Context) {
			continue
		}
		var target string
		switch d.Name {
		case "map", "split_clients":
			if len(d.Args) != 2 {
				complete = false
				continue
			}
			target = d.Args[1]
		case "set", "auth_request_set", "perl_set":
			if len(d.Args) != 2 {
				complete = false
				continue
			}
			target = d.Args[0]
		case "geo":
			if len(d.Args) > 2 {
				complete = false
				continue
			}
			target = "$geo"
			if len(d.Args) > 0 {
				target = d.Args[len(d.Args)-1]
			}
		default:
			continue
		}
		if !strings.HasPrefix(target, "$") || len(target) == 1 {
			complete = false
			continue
		}
		if custom[d.Module] == nil {
			custom[d.Module] = make(map[string]bool)
		}
		custom[d.Module][strings.ToLower(target[1:])] = true
	}
	for _, d := range directives {
		if d.Name == "real_ip_header" && slices.ContainsFunc(d.Args, func(a string) bool { return strings.EqualFold(a, "proxy_protocol") }) {
			proxyProtocol = true
		}
		if d.Name == "set_real_ip_from" || d.Name == "real_ip_header" {
			switch {
			case len(d.Args) != 1 || d.Block || d.Module != "http" ||
				(d.Context != "http" && d.Context != "server" && d.Context != "location"):
				realIP = nil
			case realIP == nil:
			case d.Name == "real_ip_header":
				realIP.Headers = append(realIP.Headers, d.Args[0])
				httpHeader = httpHeader || d.Context == "http"
			default:
				realIP.From = append(realIP.From, d.Args[0])
			}
		}
		if d.Name == "set_real_ip_from" {
			if directive == "" {
				directive, file = strings.Join(append([]string{d.Name}, d.Args...), " "), d.File
			}
			continue
		}
		if nginxDataContext(d.Context) {
			continue
		}
		if d.Name != "log_format" && d.Name != "access_log" {
			continue
		}
		if d.Module != "http" && d.Module != "stream" || d.Block {
			complete = false
			continue
		}
		switch d.Name {
		case "log_format":
			if len(d.Args) < 2 || d.Context != d.Module {
				complete = false
				continue
			}
			exact := key{d.Module, d.Args[0]}
			if seen[exact] || d.Module == "http" && d.Args[0] == "combined" {
				complete = false
				continue
			}
			seen[exact] = true
			args, escape := d.Args[1:], "default"
			if strings.HasPrefix(args[0], "escape=") {
				escape = strings.TrimPrefix(args[0], "escape=")
				args = args[1:]
			}
			value, ok := nginxFormatLogsClientValue(d.Module, escape, custom[d.Module], args...)
			if !ok {
				complete = false
				continue
			}
			name := key{d.Module, lowerASCII(d.Args[0])}
			// nginx permits case variants but binds to the first ASCII
			// case-insensitive match already declared at the use site.
			if _, exists := formats[name]; !exists {
				formats[name] = format{d, value}
			}
		case "access_log":
			contextOK := d.Context == d.Module || d.Context == "server"
			if d.Module == "http" {
				contextOK = contextOK || d.Context == "location" || d.Context == "if" || d.Context == "limit_except"
			}
			if len(d.Args) == 0 || !contextOK {
				complete = false
				continue
			}
			if d.Args[0] == "off" {
				if len(d.Args) != 1 {
					complete = false
				}
				continue
			}
			if len(d.Args) == 1 {
				// Only the HTTP module supplies an implicit combined format.
				if d.Module != "http" {
					complete = false
				}
				continue
			}
			name := key{d.Module, lowerASCII(d.Args[1])}
			if f, exists := formats[name]; exists {
				used = append(used, f)
			} else {
				complete = false
			}
		}
	}
	for _, f := range used {
		if f.value {
			return strings.Join(append([]string{f.directive.Name}, f.directive.Args...), " "), f.directive.File, complete, nil, proxyProtocol
		}
	}
	// A header in a server or location cannot prove the inherited default
	// elsewhere. Require one HTTP-level choice shared by every override.
	if !httpHeader {
		realIP = nil
	}
	return directive, file, complete, realIP, proxyProtocol
}

// NginxRealIPVerified reports whether nginx can only log a client address an
// edge vouched for: every real_ip_header is CF-Connecting-IP, which only a
// Cloudflare edge sets itself, with every set_real_ip_from inside Cloudflare's
// ranges; or every header is proxy_protocol, which the connecting proxy
// writes, with every set_real_ip_from inside web_server.trusted_proxies.
// No range may reach a loopback, unspecified or host address.
func NginxRealIPVerified(r HTTPRewrite, trusted []string) bool {
	if r.Server != platform.WSNginx || r.State != RewriteActive || r.Format || r.RealIP == nil ||
		len(r.RealIP.Headers) == 0 || len(r.RealIP.From) == 0 {
		return false
	}
	cloudflare := strings.EqualFold(r.RealIP.Headers[0], "CF-Connecting-IP")
	for _, h := range r.RealIP.Headers {
		if cloudflare && !strings.EqualFold(h, "CF-Connecting-IP") || !cloudflare && h != "proxy_protocol" {
			return false
		}
	}
	allowed := cloudflarePrefixes
	if !cloudflare {
		// Customer code on a shared edge can open TCP from the edge's own
		// addresses and write any PROXY header: only the operator's proxies.
		allowed = nil
		for _, t := range trusted {
			if p, ok := realIPPrefix(t); ok {
				allowed = append(allowed, p)
			}
		}
	}
	for _, from := range r.RealIP.From {
		p, ok := realIPPrefix(from)
		if !ok || !slices.ContainsFunc(allowed, func(q netip.Prefix) bool {
			return q.Bits() <= p.Bits() && q.Contains(p.Addr())
		}) {
			return false
		}
	}
	// This lookup is fresh and fails closed, including mapped IPv4 and
	// unspecified addresses a local process can use.
	entry, _, err := netutil.HostLocalProxyEntry(r.RealIP.From)
	return err == nil && entry == ""
}

// NginxProxyProtocol reports nginx that may take client addresses from PROXY
// protocol, in any context or in a part of the tree CSM could not read. A
// refused address from it cannot fall back to legacy blocking: customer code
// on shared edges can supply arbitrary PROXY headers.
func (r HTTPRewrite) NginxProxyProtocol() bool {
	return r.Server == platform.WSNginx && r.ProxyProtocol
}

// realIPPrefix reads an address or CIDR as a masked prefix.
func realIPPrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Zone() != "" {
			return netip.Prefix{}, false
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

// These blocks use their own entry handlers, not nginx directive lookup.
func nginxDataContext(context string) bool {
	switch context {
	case "map", "geo", "split_clients", "types":
		return true
	}
	return false
}

// lswsClientAddressRewrite returns the first LiteSpeed setting that logs a
// replaced or request-chosen client address: useIpInProxyHeader when it is
// on, or a logFormat that writes a request value where CSM reads the
// client; "" when there is none. Anything but one well-formed
// httpServerConfig document with at most one useIpInProxyHeader and
// readable formats is an error. A completed active setting is returned
// even if later XML is unreadable.
func lswsClientAddressRewrite(path string) (string, error) {
	f, err := osFS.Open(path)
	if err != nil {
		return "", fmt.Errorf("the LiteSpeed configuration %s could not be read: %w", path, err)
	}
	defer f.Close()
	active := ""
	invalid := func(why string) (string, error) {
		return active, fmt.Errorf("the LiteSpeed configuration %s %s", path, why)
	}
	dec := xml.NewDecoder(f)
	var value, format strings.Builder
	depth, roots, settings := 0, 0, 0
	inSetting, inFormat := false, false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return active, fmt.Errorf("the LiteSpeed configuration %s could not be parsed: %w", path, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if inSetting {
				return invalid("nests an element in useIpInProxyHeader")
			}
			if inFormat {
				return invalid("nests an element in logFormat")
			}
			if depth == 0 {
				if roots++; roots > 1 || t.Name.Local != "httpServerConfig" {
					return invalid("is not one httpServerConfig document")
				}
			}
			switch t.Name.Local {
			case "useIpInProxyHeader":
				if settings++; settings > 1 {
					return invalid("sets useIpInProxyHeader more than once")
				}
				inSetting = true
			case "logFormat":
				format.Reset()
				inFormat = true
			}
			depth++
		case xml.CharData:
			if depth == 0 && strings.Trim(string(t), " \t\r\n") != "" {
				return invalid("has text outside its document element")
			}
			if inSetting {
				value.Write(t)
			}
			if inFormat {
				format.Write(t)
			}
		case xml.EndElement:
			depth--
			if inSetting {
				if v := strings.TrimSpace(value.String()); v != "" && v != "0" && active == "" {
					active = "useIpInProxyHeader " + v
				}
			}
			if inFormat {
				v := strings.TrimSpace(format.String())
				logged, ok := liteSpeedFormatLogsClientValue(v, false)
				if !ok {
					return invalid("has a logFormat it cannot read")
				}
				if logged && active == "" {
					active = "logFormat " + v
				}
			}
			inSetting, inFormat = false, false
		}
	}
	if roots != 1 {
		return invalid("is not one httpServerConfig document")
	}
	if settings == 1 && active == "" {
		if v := strings.TrimSpace(value.String()); v == "" {
			return invalid("sets an empty useIpInProxyHeader")
		}
	}
	return active, nil
}
