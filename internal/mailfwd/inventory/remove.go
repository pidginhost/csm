package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/systemdrun"
)

// uapiPath is where cPanel ships uapi; the /usr/bin symlink is not present on
// every host and the service PATH is minimal.
const uapiPath = "/usr/local/cpanel/bin/uapi"

// uapiTimeout bounds one uapi call. uapi loads cPanel's Perl stack and the
// account's data on every invocation, so several seconds is normal.
const uapiTimeout = 30 * time.Second

// CPanelRemover deletes forwarders through cPanel's UAPI as the account that
// owns the domain, so cPanel updates its own caches along with the alias file.
type CPanelRemover struct {
	lookPath systemdrun.LookPathFunc
	run      systemdrun.RunnerFunc
}

// NewCPanelRemover returns a remover that runs uapi with run, outside the
// daemon's sandbox through systemd-run.
func NewCPanelRemover(lookPath systemdrun.LookPathFunc, run systemdrun.RunnerFunc) *CPanelRemover {
	return &CPanelRemover{lookPath: lookPath, run: run}
}

// Remove deletes one destination from forwarder f. f.Owner must name the
// cPanel account. uapi writes under the account home and into cPanel's
// caches, which the sandbox does not grant, so it runs only as a transient
// unit: inside the sandbox it could change the alias file and then fail.
func (r *CPanelRemover) Remove(f Forwarder, dest string) error {
	ctx, cancel := context.WithTimeout(context.Background(), uapiTimeout)
	defer cancel()
	out, err := systemdrun.Run(ctx, r.lookPath, r.run,
		systemdrun.Options{Pipe: true, Required: true, RuntimeMax: uapiTimeout},
		uapiPath, "--output=json", "--user="+f.Owner, "Email", "delete_forwarder",
		"address="+uapiValue(f.Source), "forwarder="+uapiValue(dest))
	if errors.Is(err, systemdrun.ErrUnavailable) {
		return err
	}
	return uapiReplyError(out, err)
}

// uapiValue encodes v for uapi's command line, which URI-decodes every value.
// A space goes in as %20, which reads the same whether or not the decoder
// takes + for a space.
func uapiValue(v string) string {
	return strings.ReplaceAll(url.QueryEscape(v), "+", "%20")
}

// uapiReplyError preserves cPanel's own failure message. A success reply
// cannot override a failed command: systemd-run may fail after forwarding
// the output, leaving completion uncertain.
func uapiReplyError(out []byte, runErr error) error {
	var reply struct {
		Result struct {
			Status int      `json:"status"`
			Errors []string `json:"errors"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &reply); err != nil {
		text := strings.TrimSpace(string(out))
		if len(text) > 200 {
			text = text[:200]
		}
		if runErr != nil {
			return fmt.Errorf("uapi: %w: %s", runErr, text)
		}
		return fmt.Errorf("unreadable uapi reply: %s", text)
	}
	if reply.Result.Status == 1 {
		if runErr != nil {
			return fmt.Errorf("uapi execution failed: %w", runErr)
		}
		return nil
	}
	if len(reply.Result.Errors) == 0 {
		return errors.New("uapi reported failure without an error message")
	}
	return errors.New(strings.Join(reply.Result.Errors, "; "))
}
