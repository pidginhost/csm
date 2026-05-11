package webserver

import (
	"context"
	"fmt"
	"time"

	"github.com/pidginhost/csm/internal/platform"
)

// lswsHandler manages the LiteSpeed integration. The right snippet path
// depends on how LSWS is wired:
//
//   - cPanel + LSWS:  LSWS runs with <loadApacheConf>1</loadApacheConf>
//     and reads cPanel's Apache config tree. The snippet drops at
//     /etc/apache2/conf.d/csm-challenge.conf, same as plain Apache,
//     and LSWS picks it up automatically.
//
//   - Plain LSWS (no cPanel): the operator runs LSWS in native mode
//     with /usr/local/lsws/conf/httpd_config.xml. There is no auto-
//     include dir for text-style rewrite rules; the snippet goes in
//     /usr/local/lsws/conf/templates/ and the operator must include
//     it manually via the LSWS WebAdmin Console -> Server -> General
//     -> Rewrite -> External Rewrite Rules. The installer writes the
//     file but emits a stderr note pointing at the manual step.
type lswsHandler struct {
	cmdRunner cmdRunner
	cpanel    bool
}

func newLSWSHandler(info platform.Info, r cmdRunner) *lswsHandler {
	return &lswsHandler{cmdRunner: r, cpanel: info.IsCPanel()}
}

func (h *lswsHandler) Kind() string { return "lsws" }

func (h *lswsHandler) SnippetPath() string {
	if h.cpanel {
		return "/etc/apache2/conf.d/csm-challenge.conf"
	}
	return "/usr/local/lsws/conf/templates/csm-challenge.conf"
}

func (h *lswsHandler) Template() string { return lswsTemplate }

func (h *lswsHandler) Validate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// LSWS has no `lswsctrl conftest` verb (the documented surface is
	// start|stop|restart|reload|condrestart|try-restart|status). The
	// equivalent configtest is `lshttpd -t`, which parses the active
	// config and exits non-zero on syntax errors without touching the
	// running listener.
	out, err := h.cmdRunner.Run(ctx, "/usr/local/lsws/bin/lshttpd", "-t")
	if err != nil {
		return fmt.Errorf("lsws lshttpd -t failed: %v\n%s", err, out)
	}
	return nil
}

func (h *lswsHandler) Reload() error {
	// LSWS does not have a graceful reload equivalent; `restart` is the
	// supported way to pick up new config without dropping established
	// listener sockets (LSWS's internal supervisor handles the hand-
	// off). The full-restart path is what the operator's own toolchain
	// invokes on config change too.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := h.cmdRunner.Run(ctx, "/usr/local/lsws/bin/lswsctrl", "restart")
	if err != nil {
		return fmt.Errorf("lsws restart failed: %v\n%s", err, out)
	}
	return nil
}
