package checks

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

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
// Apache RemoteIPHeader or RemoteIPProxyProtocol, an nginx set_real_ip_from,
// or LiteSpeed's client IP from header, in any scope.
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
		src.nginxConfig = filepath.Join(info.NginxConfigRoot(), "nginx.conf")
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
		value, err := lswsClientIPFromHeader(src.lswsConfig)
		switch {
		case err != nil:
			unknown = err.Error()
		case value != "":
			r.State, r.Directive, r.File = RewriteActive, "useIpInProxyHeader "+value, src.lswsConfig
			return r
		}
	}
	if src.apacheConfig != "" {
		directive, file, complete := apacheRemoteIPRewrite(src.apacheConfig)
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
		directive, file, complete := nginxRealIPRewrite(src.nginxConfig)
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

// apacheRemoteIPRewrite returns the first mod_remoteip directive that
// replaces the client address, its file, and whether the whole tree was
// read. A rewrite directive Apache would refuse leaves the tree unknown.
func apacheRemoteIPRewrite(path string) (directive, file string, complete bool) {
	lines, complete := assembleApacheConfigWithStatus(path)
	malformed := false
	valid := walkApacheLines(lines, func(line apacheConfigLine, fields []string, _ apacheLineContext) {
		if directive != "" {
			return
		}
		switch {
		case strings.EqualFold(fields[0], "RemoteIPHeader"):
			if len(fields) != 2 {
				malformed = true
				return
			}
			directive, file = strings.Join(fields, " "), line.File
		case strings.EqualFold(fields[0], "RemoteIPProxyProtocol"):
			switch {
			case len(fields) == 2 && strings.EqualFold(fields[1], "On"):
				directive, file = strings.Join(fields, " "), line.File
			case len(fields) != 2 || !strings.EqualFold(fields[1], "Off"):
				malformed = true
			}
		}
	})
	return directive, file, complete && valid && !malformed
}

// nginxRealIPRewrite returns the first set_real_ip_from, which turns on
// nginx's realip rewrite from real_ip_header or its X-Real-IP default, its
// file, and whether the whole tree was read.
func nginxRealIPRewrite(path string) (directive, file string, complete bool) {
	directives, complete := nginxDirectives(path)
	for _, d := range directives {
		if d.Name == "set_real_ip_from" {
			return strings.Join(append([]string{d.Name}, d.Args...), " "), d.File, complete
		}
	}
	return "", "", complete
}

// lswsClientIPFromHeader returns LiteSpeed's useIpInProxyHeader value when
// it is on, "" when it is off or unset. Anything but one well-formed
// httpServerConfig document with at most one plain setting is an error.
func lswsClientIPFromHeader(path string) (string, error) {
	f, err := osFS.Open(path)
	if err != nil {
		return "", fmt.Errorf("the LiteSpeed configuration %s could not be read: %w", path, err)
	}
	defer f.Close()
	invalid := func(why string) (string, error) {
		return "", fmt.Errorf("the LiteSpeed configuration %s %s", path, why)
	}
	dec := xml.NewDecoder(f)
	var value strings.Builder
	depth, roots, settings, inSetting := 0, 0, 0, false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("the LiteSpeed configuration %s could not be parsed: %w", path, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if inSetting {
				return invalid("nests an element in useIpInProxyHeader")
			}
			if depth == 0 {
				if roots++; roots > 1 || t.Name.Local != "httpServerConfig" {
					return invalid("is not one httpServerConfig document")
				}
			}
			if t.Name.Local == "useIpInProxyHeader" {
				if settings++; settings > 1 {
					return invalid("sets useIpInProxyHeader more than once")
				}
				inSetting = true
			}
			depth++
		case xml.CharData:
			if depth == 0 && strings.Trim(string(t), " \t\r\n") != "" {
				return invalid("has text outside its document element")
			}
			if inSetting {
				value.Write(t)
			}
		case xml.EndElement:
			depth--
			inSetting = false
		}
	}
	if roots != 1 {
		return invalid("is not one httpServerConfig document")
	}
	v := strings.TrimSpace(value.String())
	switch {
	case settings == 0 || v == "0":
		return "", nil
	case v == "":
		return invalid("sets an empty useIpInProxyHeader")
	}
	return v, nil
}
