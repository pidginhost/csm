package webserver

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"
)

// siteIncluder is a handler whose site blocks do not inherit the
// server-scope snippet and read the rule from a per-site include instead.
// SiteSnippetPath is empty when the host has no such include.
type siteIncluder interface {
	SiteSnippetPath() string
	SiteTemplate() string
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
// Methods are safe on a nil receiver, which means no per-site include.
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

func (c *cpanelSites) SiteTemplate() string { return cpanelSiteTemplate }

func (c *cpanelSites) SiteIncludeActive() (bool, error) {
	// #nosec G304 -- fixed cPanel httpd.conf path, or a test's temp file.
	data, err := os.ReadFile(c.httpdConf)
	if err != nil {
		return false, err
	}
	return bytes.Contains(data, []byte(cpanelSiteInclude)), nil
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
