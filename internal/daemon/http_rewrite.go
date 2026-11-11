package daemon

import (
	"sync"

	"github.com/pidginhost/csm/internal/checks"
	csmlog "github.com/pidginhost/csm/internal/log"
	"github.com/pidginhost/csm/internal/platform"
)

// detectHostHTTPRewrite reads this host's web server configuration.
var detectHostHTTPRewrite = func() checks.HTTPRewrite { return checks.DetectHTTPRewrite(platform.Detect()) }

// rewriteMu orders each read of the web server with its publication, so a
// slower read never overwrites a newer one. The state is process-wide.
var rewriteMu sync.Mutex

// refreshHTTPRewrite publishes whether the web server rewrites the client
// address it logs, and logs a change.
func (d *Daemon) refreshHTTPRewrite() {
	rewriteMu.Lock()
	defer rewriteMu.Unlock()
	r := detectHostHTTPRewrite()
	if prev := checks.CurrentHTTPRewrite(); prev != r {
		csmlog.Info("web server client address rewriting", "state", r.State.String(), "server", string(r.Server), "directive", r.Directive, "file", r.File, "reason", r.Reason)
	}
	checks.SetHTTPRewrite(r)
}
