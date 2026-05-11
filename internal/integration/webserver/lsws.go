package webserver

import (
	"context"
	"fmt"
	"time"
)

// lswsHandler manages the LiteSpeed integration. LSWS reads its config
// from `httpd_config.conf` so the snippet drop-in is a template file
// that operators include via a single `include` line set at install
// time. Once that include exists, CSM writes the snippet body at the
// canonical path and reloads.
type lswsHandler struct {
	cmdRunner cmdRunner
}

func newLSWSHandler(r cmdRunner) *lswsHandler {
	return &lswsHandler{cmdRunner: r}
}

func (h *lswsHandler) Kind() string { return "lsws" }
func (h *lswsHandler) SnippetPath() string {
	return "/usr/local/lsws/conf/templates/csm-challenge.conf"
}
func (h *lswsHandler) Template() string { return lswsTemplate }

func (h *lswsHandler) Validate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := h.cmdRunner.Run(ctx, "/usr/local/lsws/bin/lswsctrl", "conftest")
	if err != nil {
		return fmt.Errorf("lsws conftest failed: %v\n%s", err, out)
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
