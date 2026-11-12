package webserver

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// siteIncluder is a handler whose site blocks do not inherit the
// server-scope snippet and read the rule from a per-site include instead.
// SiteSnippetPath is empty when the host has no such include.
type siteIncluder interface {
	SiteSnippetPath() string
	SiteTemplate() string
	// SiteConfigPath is the generated configuration changed by a rebuild,
	// or empty where the operator adds the includes and nothing rebuilds.
	SiteConfigPath() string
	// SiteScope names the site blocks that need the include.
	SiteScope() string
	// SiteFix is what the operator does while they do not read it.
	SiteFix() string
	// SiteIncludeActive reports whether the site blocks read the include.
	SiteIncludeActive() (bool, error)
	// RebuildSiteIncludes regenerates the web server configuration so its
	// site blocks read the include.
	RebuildSiteIncludes() error
}

const (
	cpanelSiteSnippetPath = "/etc/apache2/conf.d/userdata/csm-challenge.conf"
	cpanelSiteInclude     = `Include "/etc/apache2/conf.d/userdata/*.conf"`
	cpanelHTTPDConf       = "/etc/apache2/conf/httpd.conf"
	cpanelRebuildHTTPD    = "/usr/local/cpanel/scripts/rebuildhttpdconf"
)

// cpanelSites covers cPanel's site blocks, under Apache or LiteSpeed.
// Port-80 blocks inherit the server-scope snippet; HTTPS blocks do not, so
// the rule also goes in the per-site include. cPanel adds that include to
// every block only when it regenerates httpd.conf with a file present.
// SiteSnippetPath returns an empty path on a nil receiver to opt out.
type cpanelSites struct {
	httpdConf string
	runner    cmdRunner
}

func newCPanelSites(r cmdRunner) *cpanelSites {
	return &cpanelSites{httpdConf: cpanelHTTPDConf, runner: r}
}

func (c *cpanelSites) SiteSnippetPath() string {
	if c == nil {
		return ""
	}
	return cpanelSiteSnippetPath
}

func (c *cpanelSites) SiteTemplate() string { return siteTemplate }

func (c *cpanelSites) SiteConfigPath() string { return c.httpdConf }

func (c *cpanelSites) SiteScope() string { return "HTTPS sites" }

func (c *cpanelSites) SiteFix() string { return "run `csm webserver-integration upgrade`" }

func (c *cpanelSites) SiteIncludeActive() (bool, error) {
	// #nosec G304 -- fixed cPanel httpd.conf path, or a test's temp file.
	data, err := os.ReadFile(c.httpdConf)
	if err != nil {
		return false, err
	}
	return cpanelHTTPSIncludes(string(data)), nil
}

// cpanelUserSiteMarker is the per-user include path cPanel writes into every
// user site block, active or as a commented example. The server's own
// hostname blocks carry none and never get the global include, so they do
// not count against coverage.
const cpanelUserSiteMarker = "/etc/apache2/conf.d/userdata/ssl/"

// cPanel emits its sites inline. A global include, a commented example, or
// an HTTP-only include does not establish coverage of the HTTPS sites.
func cpanelHTTPSIncludes(conf string) bool {
	inSite, tls, userSite, included := false, false, false, false
	for _, line := range strings.Split(conf, "\n") {
		if inSite && strings.Contains(line, cpanelUserSiteMarker) {
			userSite = true
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "<virtualhost":
			inSite, tls, userSite, included = true, false, false, false
			for _, addr := range fields[1:] {
				if strings.HasSuffix(strings.TrimSuffix(addr, ">"), ":443") {
					tls = true
				}
			}
		case "</virtualhost>":
			if inSite && tls && userSite {
				if !included {
					return false
				}
			}
			inSite = false
		case "sslengine":
			if inSite && len(fields) == 2 && strings.EqualFold(fields[1], "on") {
				tls = true
			}
		case "include", "includeoptional":
			if inSite && len(fields) == 2 && strings.Trim(fields[1], "\"'") == "/etc/apache2/conf.d/userdata/*.conf" {
				included = true
			}
		}
	}
	// No user HTTPS site means nothing to cover yet: a site added later gets
	// the include when cPanel builds its block with the file present.
	return !inSite
}

func (c *cpanelSites) RebuildSiteIncludes() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := c.runner.Run(ctx, cpanelRebuildHTTPD)
	if err != nil {
		return fmt.Errorf("rebuild httpd.conf: %v\n%s", err, out)
	}
	return nil
}

// plainApacheSiteSnippetPath lives beside the challenge maps: the daemon may
// write there, it survives daemon stops, and Apache never loads it on its
// own, only through the Include line each site block carries.
const plainApacheSiteSnippetPath = "/var/cache/csm/apache-challenge-site.conf"

// plainApacheSites covers Apache without cPanel. No site block inherits the
// server-wide snippet and CSM does not edit operator site files, so the
// operator adds the Include line to each <VirtualHost>.
type plainApacheSites struct {
	ctl    string
	runner cmdRunner
}

func (p *plainApacheSites) SiteSnippetPath() string { return plainApacheSiteSnippetPath }

func (p *plainApacheSites) SiteTemplate() string { return siteTemplate }

func (p *plainApacheSites) SiteConfigPath() string { return "" }

func (p *plainApacheSites) SiteScope() string { return "Apache sites" }

func (p *plainApacheSites) SiteFix() string {
	return "add `Include " + plainApacheSiteSnippetPath + "` inside every <VirtualHost>, then reload Apache"
}

func (p *plainApacheSites) RebuildSiteIncludes() error {
	return fmt.Errorf("apache site blocks need `Include %s` added by the operator", plainApacheSiteSnippetPath)
}

// SiteIncludeActive reads every file Apache loads and requires each
// <VirtualHost> in them to include the snippet. A server with no site block
// has nothing to cover.
func (p *plainApacheSites) SiteIncludeActive() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := p.runner.Run(ctx, p.ctl, "-t", "-D", "DUMP_INCLUDES")
	if err != nil {
		return false, fmt.Errorf("%s -t -D DUMP_INCLUDES: %v\n%s", p.ctl, err, out)
	}
	root, err := parseApacheIncludes(string(out))
	if err != nil {
		return false, err
	}
	coverage := apacheSiteCoverage{}
	if err := coverage.visit(root); err != nil {
		return false, err
	}
	return !coverage.inSite && !coverage.missing, nil
}
