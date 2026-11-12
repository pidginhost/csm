package checks

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"

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
func SetHTTPRewrite(r HTTPRewrite) { httpRewrite.Store(&r) }

// CurrentHTTPRewrite is the published state, unknown before the first.
func CurrentHTTPRewrite() HTTPRewrite {
	if r := httpRewrite.Load(); r != nil {
		return *r
	}
	return HTTPRewrite{}
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
// header, in any scope; failing those, a log format that writes a request
// value where CSM reads the client.
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
			r.State, r.Directive, r.File = RewriteActive, directive, src.lswsConfig
			return r
		case err != nil:
			unknown = err.Error()
		}
	}
	if src.apacheConfig != "" {
		directive, file, complete := apacheClientAddressRewrite(src.apacheConfig)
		if directive != "" {
			r.State, r.Directive, r.File = RewriteActive, directive, file
			return r
		}
		if !complete && unknown == "" {
			unknown = "the Apache configuration " + src.apacheConfig + " could not be read completely"
		}
	} else if src.apacheRequired && unknown == "" {
		unknown = "no Apache configuration file was found"
	}
	if src.nginxConfig != "" {
		directive, file, complete := nginxClientAddressRewrite(src.nginxConfig)
		if directive != "" {
			r.State, r.Directive, r.File = RewriteActive, directive, file
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

// apacheClientAddressRewrite returns the first directive that replaces the
// client address, its file, and whether the whole tree was read: a
// mod_remoteip header or PROXY protocol, a loaded or configured
// mod_cloudflare, or an enabled mod_rpaf (0.6 or 0.8 names); failing
// those, a log format that writes a request value where CSM reads the
// client. A rewrite or format directive Apache would refuse leaves the
// tree unknown.
func apacheClientAddressRewrite(path string) (directive, file string, complete bool) {
	lines, complete := assembleApacheConfigWithStatus(path)
	malformed := false
	var logs apacheLogFormats
	valid := walkApacheLines(lines, func(line apacheConfigLine, fields []string, _ apacheLineContext) {
		if directive != "" {
			return
		}
		logs.add(line, fields)
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
			if len(fields) != 2 {
				malformed = true
				return
			}
			directive, file = strings.Join(fields, " "), line.File
		case is("CloudFlareRemoteIPTrustedProxy"):
			if len(fields) < 2 {
				malformed = true
				return
			}
			directive, file = strings.Join(fields, " "), line.File
		case is("LoadModule") && len(fields) > 1 && apacheArgumentHasVariable(fields[1]):
			// Only Apache can resolve its Define and environment values.
			malformed = true
		case is("LoadModule") && len(fields) > 1 && fields[1] == "cloudflare_module":
			if len(fields) != 3 {
				malformed = true
				return
			}
			// mod_cloudflare trusts its built-in Cloudflare ranges once loaded.
			directive, file = strings.Join(fields, " "), line.File
		case is("RemoteIPProxyProtocol", "RPAF_Enable", "RPAFenable"):
			switch {
			case len(fields) == 2 && strings.EqualFold(fields[1], "On"):
				directive, file = strings.Join(fields, " "), line.File
			case len(fields) != 2 || !strings.EqualFold(fields[1], "Off"):
				malformed = true
			}
		}
	})
	if directive == "" {
		if f := logs.clientValue(); f != nil {
			directive, file = f.directive, f.file
		}
	}
	return directive, file, complete && valid && !malformed && !logs.malformed
}

// nginxClientAddressRewrite returns the first set_real_ip_from, which
// turns on nginx's realip rewrite from real_ip_header or its X-Real-IP
// default; failing that, the first log_format an access_log writes that
// logs a request value where CSM reads the client. It also returns the
// file and whether the tree and its format framing could be read. HTTP
// and stream have separate namespaces; only HTTP has built-in combined.
func nginxClientAddressRewrite(path string) (directive, file string, complete bool) {
	directives, complete := nginxDirectives(path)
	type format struct {
		directive nginxDirective
		value     bool
	}
	type key struct{ module, name string }
	formats := make(map[key][]format)
	seen := make(map[key]bool)
	var used []key
	// Optional modules can leave their variable names available for user
	// definitions. A familiar spelling alone does not prove a peer value.
	custom := make(map[string]map[string]bool)
	for _, d := range directives {
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
		if d.Name == "set_real_ip_from" {
			return strings.Join(append([]string{d.Name}, d.Args...), " "), d.File, complete
		}
		if d.Name != "log_format" && d.Name != "access_log" {
			continue
		}
		if d.Module != "http" && d.Module != "stream" {
			complete = false
			continue
		}
		switch d.Name {
		case "log_format":
			if len(d.Args) < 2 {
				complete = false
				continue
			}
			exact := key{d.Module, d.Args[0]}
			if seen[exact] || d.Module == "http" && d.Args[0] == "combined" {
				complete = false
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
			name := key{d.Module, strings.ToLower(d.Args[0])}
			formats[name] = append(formats[name], format{d, value})
		case "access_log":
			if len(d.Args) == 0 {
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
			name := key{d.Module, strings.ToLower(d.Args[1])}
			if name.module == "http" && name.name == "combined" {
				continue
			}
			used = append(used, name)
		}
	}
	for _, name := range used {
		if len(formats[name]) == 0 {
			complete = false
		}
		for _, f := range formats[name] {
			if f.value {
				return strings.Join(append([]string{f.directive.Name}, f.directive.Args...), " "), f.directive.File, complete
			}
		}
	}
	return "", "", complete
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
				logged, ok := apacheFormatLogsClientValue(v, false)
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
