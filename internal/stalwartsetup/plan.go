// Package stalwartsetup works out what a Stalwart server needs before CSM can
// rely on it, and applies it. Inspect only reads; Apply writes the changes
// Inspect planned and reloads Stalwart's settings once.
package stalwartsetup

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/stalwartapi"
)

// API is the part of the Stalwart admin API setup uses.
type API interface {
	TracingLevels(ctx context.Context) ([]stalwartapi.TracingLevel, error)
	SetTracingLevel(ctx context.Context, id, event, level string) error
	HTTPSettings(ctx context.Context) (stalwartapi.HTTPSettings, error)
	SetHTTPSettings(ctx context.Context, h stalwartapi.HTTPSettings) error
	BanPeriods(ctx context.Context) (stalwartapi.BanPeriods, error)
	SetBanPeriods(ctx context.Context, d time.Duration) error
	Listeners(ctx context.Context) ([]stalwartapi.Listener, error)
	ProxyTrustedNetworks(ctx context.Context) ([]string, error)
	ReloadSettings(ctx context.Context) ([]string, error)
}

// Inputs is what CSM knows about itself.
type Inputs struct {
	// BlockExpiry is CSM's block length; Stalwart's bans are set to it.
	BlockExpiry time.Duration
	// LockManaged is true when the running daemon manages the firewall.
	LockManaged bool
	// LockedPorts are the ports the running firewall locks to listed users.
	LockedPorts []int
	// WebUsers are the web server's users, for the lock line setup suggests.
	WebUsers []string
}

// State is a step's outcome.
type State string

const (
	Done    State = "done"
	Change  State = "change"
	Skipped State = "skipped"
	Unsafe  State = "unsafe"
	Warn    State = "warn"
)

// Step is one setup step.
type Step struct {
	Name   string
	State  State
	Detail string
	apply  func(ctx context.Context, api API) error
}

// Plan is the setup steps in order.
type Plan struct {
	Steps         []Step
	pendingReload bool
}

const (
	failedLoginEvent = "auth.failed"
	stalwartUser     = "stalwart"
)

// ErrNotReloaded means Stalwart stored the settings Apply wrote but did not
// reload them. A later Inspect reads them as done, so the caller must tell
// the operator to restart Stalwart.
var ErrNotReloaded = errors.New("settings stored but not reloaded")

// Inspect reads Stalwart's settings and plans each step. It writes nothing.
func Inspect(ctx context.Context, api API, in Inputs) (Plan, error) {
	levels, err := api.TracingLevels(ctx)
	if err != nil {
		return Plan{}, err
	}
	httpSettings, err := api.HTTPSettings(ctx)
	if err != nil {
		return Plan{}, err
	}
	listeners, err := api.Listeners(ctx)
	if err != nil {
		return Plan{}, err
	}
	bans, err := api.BanPeriods(ctx)
	if err != nil {
		return Plan{}, err
	}
	proxy, err := api.ProxyTrustedNetworks(ctx)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Steps: []Step{
		failedLoginStep(levels),
		clientAddressStep(httpSettings, listeners, in),
		banExpiryStep(bans, in.BlockExpiry),
		proxyStep(listeners, proxy),
	}}, nil
}

// Apply makes each planned change in order, then reloads Stalwart's settings
// once. It makes no call when nothing changes. A failed write stops it, and
// the settings written before it are still reloaded: a later run reads them
// as done, so they must not be left stored but inactive.
func (p *Plan) Apply(ctx context.Context, api API) ([]string, error) {
	var failed error
	for i := range p.Steps {
		s := &p.Steps[i]
		if s.State != Change || s.apply == nil {
			continue
		}
		if err := s.apply(ctx, api); err != nil {
			failed = fmt.Errorf("%s: %w", s.Name, err)
			break
		}
		p.pendingReload = true
		s.apply = nil
	}
	if !p.pendingReload {
		return nil, failed
	}
	warnings, err := api.ReloadSettings(ctx)
	if err != nil {
		return nil, errors.Join(failed, fmt.Errorf("%w: %w", ErrNotReloaded, err))
	}
	p.pendingReload = false
	return warnings, failed
}

func failedLoginStep(levels []stalwartapi.TracingLevel) Step {
	s := Step{Name: "failed-login logging"}
	id, level := "", ""
	for _, l := range levels {
		if l.Event == failedLoginEvent {
			id, level = l.ID, l.Level
			break
		}
	}
	switch level {
	case "info", "warn", "error":
		s.State, s.Detail = Done, fmt.Sprintf("%s is logged at %s", failedLoginEvent, level)
		return s
	case "":
		s.Detail = fmt.Sprintf("%s has no log level of its own; set it to info", failedLoginEvent)
	default:
		s.Detail = fmt.Sprintf("%s is logged at %s; set it to info", failedLoginEvent, level)
	}
	s.State = Change
	s.apply = func(ctx context.Context, api API) error {
		return api.SetTracingLevel(ctx, id, failedLoginEvent, "info")
	}
	return s
}

// clientAddressStep decides whether Stalwart's HTTP listeners may take the
// client address from X-Forwarded-For. That is only safe when every HTTP
// listener is reachable from this host alone and CSM's running firewall lets
// only the web server and Stalwart connect to it: otherwise anyone who can
// connect can claim any address.
func clientAddressStep(h stalwartapi.HTTPSettings, listeners []stalwartapi.Listener, in Inputs) Step {
	s := Step{Name: "webmail client addresses"}
	forwarded := h.ClientIPSource != "" && h.ClientIPSource != "peer"

	var ports []int
	var public []string
	for _, l := range listeners {
		if l.Protocol != "http" {
			continue
		}
		if len(l.Bind) == 0 {
			public = append(public, l.Name+" has no known bind address")
		}
		for _, b := range l.Bind {
			if !b.Addr().Unmap().IsLoopback() {
				public = append(public, fmt.Sprintf("%s binds %s", l.Name, b))
			}
			if p := int(b.Port()); !slices.Contains(ports, p) {
				ports = append(ports, p)
			}
		}
	}
	if len(ports) == 0 && len(public) == 0 {
		s.State, s.Detail = Done, "Stalwart has no HTTP listener"
		return s
	}
	slices.Sort(ports)

	reason := ""
	switch {
	case len(public) > 0:
		reason = fmt.Sprintf("listener %s, reachable from other hosts; bind every HTTP listener to 127.0.0.1 behind the web server first",
			strings.Join(public, ", listener "))
	case !in.LockManaged || !allLocked(ports, in.LockedPorts):
		state := "CSM's running firewall does not lock the webmail port"
		if !in.LockManaged {
			state = "CSM's daemon is not managing the firewall"
		}
		reason = fmt.Sprintf("%s; add %s under firewall in csm.yaml and restart CSM", state, lockLine(ports, in.WebUsers))
	}

	switch {
	case reason != "" && forwarded:
		s.State = Unsafe
		s.Detail = fmt.Sprintf("Stalwart takes client addresses from %s, which anyone who can connect can forge: %s; until then set it back to peer in Stalwart",
			h.ClientIPSource, reason)
	case reason != "":
		s.State, s.Detail = Skipped, reason
	case h == safeForwarded:
		s.State, s.Detail = Done, "client addresses come from X-Forwarded-For (1 hop) behind CSM's port lock"
	default:
		s.State = Change
		s.Detail = "client addresses are the web server's; take them from X-Forwarded-For (1 hop). " + webServerHeader
		if forwarded {
			// More hops, or a header the web server does not set, lets the
			// client choose the address Stalwart reads.
			s.Detail = fmt.Sprintf("client addresses come from %s with %d hops, which a client can forge; take them from X-Forwarded-For (1 hop). %s",
				h.ClientIPSource, h.ForwardedHops, webServerHeader)
		}
		s.apply = func(ctx context.Context, api API) error {
			return api.SetHTTPSettings(ctx, safeForwarded)
		}
	}
	return s
}

// webServerHeader is the condition setup cannot check: with one hop Stalwart
// reads the last X-Forwarded-For entry, which must be the web server's own.
const webServerHeader = "The web server must set the header itself, as nginx does with proxy_set_header X-Forwarded-For $remote_addr or $proxy_add_x_forwarded_for; without it a client chooses the address"

// safeForwarded takes the address the web server, the only hop, appends.
var safeForwarded = stalwartapi.HTTPSettings{ClientIPSource: "xForwardedFor", ForwardedHops: 1}

func allLocked(ports, locked []int) bool {
	for _, p := range ports {
		if !slices.Contains(locked, p) {
			return false
		}
	}
	return true
}

// lockLine is the csm.yaml line that locks ports to the web users and
// Stalwart.
func lockLine(ports []int, webUsers []string) string {
	users := slices.Clone(webUsers)
	if !slices.Contains(users, stalwartUser) {
		users = append(users, stalwartUser)
	}
	entries := make([]string, len(ports))
	for i, p := range ports {
		entries[i] = strconv.Quote(strconv.Itoa(p) + ":" + strings.Join(users, ","))
	}
	return "local_port_locks: [" + strings.Join(entries, ", ") + "]"
}

func banExpiryStep(b stalwartapi.BanPeriods, want time.Duration) Step {
	s := Step{Name: "ban expiry"}
	if want <= 0 {
		s.State, s.Detail = Skipped, "CSM has no block length"
		return s
	}
	same := func(d *time.Duration) bool { return d != nil && *d == want }
	if same(b.Auth) && same(b.Abuse) && same(b.Scan) {
		s.State, s.Detail = Done, fmt.Sprintf("failed-login, abuse and scan bans last %s, as CSM's blocks do", fmtPeriod(&want))
		return s
	}
	s.State = Change
	s.Detail = fmt.Sprintf("failed-login bans last %s, abuse %s, scan %s; set them to CSM's block length, %s",
		fmtPeriod(b.Auth), fmtPeriod(b.Abuse), fmtPeriod(b.Scan), fmtPeriod(&want))
	s.apply = func(ctx context.Context, api API) error { return api.SetBanPeriods(ctx, want) }
	return s
}

func fmtPeriod(d *time.Duration) string {
	switch {
	case d == nil:
		return "permanent"
	case *d%time.Hour == 0:
		return strconv.FormatInt(int64(*d/time.Hour), 10) + "h"
	case *d%time.Minute == 0:
		return strconv.FormatInt(int64(*d/time.Minute), 10) + "m"
	}
	return d.String()
}

// proxyStep reports mail listeners that accept the PROXY protocol: their log
// addresses come from the proxy's header, which CSM does not handle yet.
func proxyStep(listeners []stalwartapi.Listener, global []string) Step {
	s := Step{Name: "proxy protocol listeners"}
	var names []string
	for _, l := range listeners {
		if l.Protocol == "http" {
			continue
		}
		if len(l.ProxyNetworks) > 0 || len(global) > 0 {
			names = append(names, l.Name)
		}
	}
	if len(names) == 0 {
		s.State, s.Detail = Done, "no mail listener accepts the PROXY protocol"
		return s
	}
	s.State = Warn
	s.Detail = fmt.Sprintf("%s accept the PROXY protocol; CSM still blocks the addresses they log, so make sure only your proxies are trusted",
		strings.Join(names, ", "))
	return s
}
