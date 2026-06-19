package daemon

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

const (
	// cpdoveauthdSocketPath is the cPanel dovecot auth daemon's unix socket.
	cpdoveauthdSocketPath = "/usr/local/cpanel/var/cpdoveauthd.sock"
	// mailAuthProbeInterval is how often the prober dials the socket.
	mailAuthProbeInterval = 20 * time.Second
	// mailAuthRestartCooldown is the minimum gap between restart attempts.
	mailAuthRestartCooldown = 2 * time.Minute
)

// dialMailAuthBackend probes the cpdoveauthd unix socket. A successful connect
// means the auth backend can answer; a refused/missing socket means it is down.
func dialMailAuthBackend() bool {
	c, err := net.DialTimeout("unix", cpdoveauthdSocketPath, 3*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// restartMailAuthBackend runs the operator-configured restart command.
func restartMailAuthBackend(command string) error {
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("restart command is empty")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Run through the shell so operators can use normal service commands with
	// arguments, such as "systemctl restart dovecot".
	// #nosec G204 -- command is operator-configured in root-owned csm.yaml.
	return exec.CommandContext(ctx, "/bin/sh", "-c", command).Run()
}

// authBackendHealth tracks reachability of the mail authentication backend
// (cPanel's cpdoveauthd unix socket) via an active probe. While the backend is
// down every mail and SMTP login fails regardless of credentials, so callers
// gate brute-force auto-block on Degraded() to avoid mass-blocking legitimate
// users. chkservd only checks dovecot's listen ports, which stay up during a
// cpdoveauthd outage, so this probe covers a failure mode cPanel's own
// monitoring misses. When restartEnabled, a sustained outage (continuously down
// for at least downGrace) triggers a rate-limited service restart to self-heal.
type authBackendHealth struct {
	mu      sync.Mutex
	now     func() time.Time
	probe   func() bool  // true = backend reachable
	restart func() error // run the configured restart command

	restartEnabled     bool
	downGrace          time.Duration
	restartCooldown    time.Duration
	maxRestartsPerHour int

	downSince        time.Time // zero == backend currently up
	alerted          bool      // down alert already emitted for the current outage
	lastRestart      time.Time
	restartsThisHour int
	hourKey          string
}

func newAuthBackendHealth(
	now func() time.Time,
	probe func() bool,
	restart func() error,
	restartEnabled bool,
	downGrace time.Duration,
	restartCooldown time.Duration,
	maxRestartsPerHour int,
) *authBackendHealth {
	if now == nil {
		now = time.Now
	}
	return &authBackendHealth{
		now:                now,
		probe:              probe,
		restart:            restart,
		restartEnabled:     restartEnabled,
		downGrace:          downGrace,
		restartCooldown:    restartCooldown,
		maxRestartsPerHour: maxRestartsPerHour,
	}
}

// Degraded reports whether the mail auth backend is currently unreachable.
// Brute-force trackers consult this and suppress auto-block while it is true.
func (h *authBackendHealth) Degraded() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.downSince.IsZero()
}

// Observe runs one probe cycle and returns any findings to dispatch: a one-shot
// down alert when an outage starts, and a restart action once the outage is
// sustained past the grace period (subject to cooldown and the hourly cap).
func (h *authBackendHealth) Observe() []alert.Finding {
	now := h.now()
	reachable := h.probe != nil && h.probe()

	h.mu.Lock()

	if reachable {
		h.downSince = time.Time{}
		h.alerted = false
		h.mu.Unlock()
		return nil
	}

	var out []alert.Finding
	var runRestart bool
	var restart func() error
	if h.downSince.IsZero() {
		h.downSince = now
	}
	if !h.alerted {
		h.alerted = true
		out = append(out, alert.Finding{
			Severity:  alert.Warning,
			Check:     "mail_auth_backend_degraded",
			Message:   "Mail auth backend (cpdoveauthd) unreachable; mail and SMTP brute-force auto-block paused",
			Details:   "CSM could not connect to the cPanel dovecot auth socket. Logins fail regardless of password. Dovecot's listen ports stay up during this fault, so chkservd does not catch it; investigate the auth daemon.",
			Timestamp: now,
		})
	}

	if h.restartEnabled && h.restart != nil && now.Sub(h.downSince) >= h.downGrace && h.allowRestart(now) {
		h.lastRestart = now
		h.restartsThisHour++
		restart = h.restart
		runRestart = true
	}
	h.mu.Unlock()

	if runRestart {
		if err := restart(); err != nil {
			out = append(out, alert.Finding{
				Severity:  alert.High,
				Check:     "auto_response",
				Message:   fmt.Sprintf("AUTO-RESTART failed: mail auth backend down >%v and restart errored", h.downGrace),
				Details:   fmt.Sprintf("Error: %v. Manual intervention required to restore mail authentication.", err),
				Timestamp: now,
			})
		} else {
			out = append(out, alert.Finding{
				Severity:  alert.Warning,
				Check:     "auto_response",
				Message:   fmt.Sprintf("AUTO-RESTART: mail auth backend down >%v, restarted the mail service", h.downGrace),
				Details:   "cpdoveauthd was unreachable beyond the grace period; CSM restarted the mail service to recover authentication.",
				Timestamp: now,
			})
		}
	}
	return out
}

// allowRestart reports whether a restart may run now, enforcing the per-hour cap
// and the cooldown between attempts. Caller must hold h.mu.
func (h *authBackendHealth) allowRestart(now time.Time) bool {
	key := now.Format("2006-01-02T15")
	if h.hourKey != key {
		h.hourKey = key
		h.restartsThisHour = 0
	}
	if h.maxRestartsPerHour <= 0 {
		return false
	}
	if h.restartsThisHour >= h.maxRestartsPerHour {
		return false
	}
	if !h.lastRestart.IsZero() && now.Sub(h.lastRestart) < h.restartCooldown {
		return false
	}
	return true
}
