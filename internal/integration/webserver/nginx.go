package webserver

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/pidginhost/csm/internal/systemdrun"
)

// nginxHandler manages the nginx integration. The snippet lands in
// /etc/nginx/conf.d/ where stock nginx auto-includes everything via
// the default http{} include glob. Validation uses `nginx -t`, run
// outside the service sandbox; reload uses `systemctl reload nginx` so
// existing connections drain gracefully.
type nginxHandler struct {
	cmdRunner cmdRunner
	lookPath  systemdrun.LookPathFunc
}

func newNginxHandler(r cmdRunner) *nginxHandler {
	return &nginxHandler{cmdRunner: r, lookPath: exec.LookPath}
}

func (h *nginxHandler) Kind() string        { return "nginx" }
func (h *nginxHandler) SnippetPath() string { return "/etc/nginx/conf.d/csm-challenge.conf" }
func (h *nginxHandler) Template() string    { return nginxTemplate }

// PostInstallInstructions reminds the operator that the http{}
// snippet only ships the shared map; each guarded server{} block has
// to opt in with a one-line if-redirect. Nginx cannot apply this
// safely from an http{} drop-in.
func (h *nginxHandler) PostInstallInstructions() string {
	return `Nginx detected. Per-server opt-in required so http{} drop-ins do
not blind-redirect already-protected hosts. For each server{} that
should respect the challenge:

    server {
        ...
        if ($csm_challenged) {
            return 302 <challenge.public_url>?dest=$scheme://$host$request_uri;
        }
    }

Then run: nginx -t && systemctl reload nginx`
}

const nginxConfigtestTimeout = 15 * time.Second

func (h *nginxHandler) Validate() error {
	// The availability probe must not consume nginx's configtest budget.
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, nginxConfigtestTimeout)
		defer cancel()
		return h.cmdRunner.Run(ctx, name, args...)
	}
	// nginx -t opens its log files for writing, which the
	// daemon's read-only service sandbox refuses.
	out, err := systemdrun.Run(context.Background(), h.lookPath, run,
		systemdrun.Options{Pipe: true, RuntimeMax: nginxConfigtestTimeout}, "nginx", "-t")
	if err != nil {
		return fmt.Errorf("nginx configtest failed: %v\n%s", err, out)
	}
	return nil
}

func (h *nginxHandler) Reload() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := h.cmdRunner.Run(ctx, "systemctl", "reload", "nginx")
	if err != nil {
		return fmt.Errorf("nginx reload failed: %v\n%s", err, out)
	}
	return nil
}
