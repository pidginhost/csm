package webserver

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/pidginhost/csm/internal/platform"
)

// apacheHandler covers cPanel + plain Apache. cPanel ships `apachectl`
// pointing at the EasyApache binary; plain Apache on Debian/Ubuntu has
// `apache2ctl`. The selector picks the right one at construction.
type apacheHandler struct {
	snippetPath  string
	ctlBinary    string // "apachectl" or "apache2ctl"
	reloadAction []string
	cmdRunner    cmdRunner
}

func newApacheHandler(info platform.Info, r cmdRunner) *apacheHandler {
	h := &apacheHandler{cmdRunner: r}
	switch {
	case info.IsCPanel():
		// cPanel always runs EasyApache, conf.d is the canonical drop-in.
		h.snippetPath = "/etc/apache2/conf.d/csm-challenge.conf"
		h.ctlBinary = "apachectl"
		h.reloadAction = []string{"apachectl", "graceful"}
	case info.IsDebianFamily():
		// Debian/Ubuntu use apache2 + conf-enabled.
		h.snippetPath = "/etc/apache2/conf-enabled/csm-challenge.conf"
		h.ctlBinary = "apache2ctl"
		h.reloadAction = []string{"systemctl", "reload", "apache2"}
	default:
		// RHEL family without cPanel: httpd + /etc/httpd/conf.d.
		h.snippetPath = "/etc/httpd/conf.d/csm-challenge.conf"
		h.ctlBinary = "apachectl"
		h.reloadAction = []string{"systemctl", "reload", "httpd"}
	}
	return h
}

func (h *apacheHandler) Kind() string                    { return "apache" }
func (h *apacheHandler) SnippetPath() string             { return h.snippetPath }
func (h *apacheHandler) Template() string                { return apacheTemplate }
func (h *apacheHandler) PostInstallInstructions() string { return "" }

func (h *apacheHandler) Validate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := h.cmdRunner.Run(ctx, h.ctlBinary, "configtest")
	if err != nil {
		return fmt.Errorf("apache configtest failed: %v\n%s", err, out)
	}
	return nil
}

func (h *apacheHandler) Reload() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := h.cmdRunner.Run(ctx, h.reloadAction[0], h.reloadAction[1:]...)
	if err != nil {
		return fmt.Errorf("apache reload failed: %v\n%s", err, out)
	}
	return nil
}

// cmdRunner is the injection seam tests use to mock exec. The real
// implementation in realCmdRunner just shells out via os/exec.
type cmdRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type realCmdRunner struct{}

func (realCmdRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	// #nosec G204 -- name + args come from the installer's static handler
	// definitions (apachectl/apache2ctl/nginx/lswsctrl + verbs). No
	// user-controlled strings reach this path.
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
