package stalwartapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

// TracingLevel is one per-event log level override.
type TracingLevel struct {
	ID    string `json:"id"`
	Event string `json:"event"`
	Level string `json:"level"`
}

// TracingLevels lists the per-event log level overrides.
func (c *Client) TracingLevels(ctx context.Context) ([]TracingLevel, error) {
	var list []TracingLevel
	if err := c.get(ctx, "x:EventTracingLevel/get", nil, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// SetTracingLevel sets the log level of event: it updates the override id,
// or creates one when id is empty.
func (c *Client) SetTracingLevel(ctx context.Context, id, event, level string) error {
	args := map[string]any{"update": map[string]any{id: map[string]any{"level": level}}}
	if id == "" {
		args = map[string]any{"create": map[string]any{"c": map[string]any{"event": event, "level": level}}}
	}
	_, err := c.set(ctx, "x:EventTracingLevel/set", args)
	return err
}

// HTTPSettings is where the HTTP listener takes the client address from.
type HTTPSettings struct {
	ClientIPSource string `json:"clientIpSource"`
	ForwardedHops  int    `json:"forwardedHops"`
}

// HTTPSettings reads the HTTP client address settings.
func (c *Client) HTTPSettings(ctx context.Context) (HTTPSettings, error) {
	var h HTTPSettings
	err := c.getSingleton(ctx, "x:Http/get", &h)
	return h, err
}

// SetHTTPSettings writes the HTTP client address settings.
func (c *Client) SetHTTPSettings(ctx context.Context, h HTTPSettings) error {
	patch := map[string]any{"clientIpSource": h.ClientIPSource}
	if h.ForwardedHops > 0 {
		patch["forwardedHops"] = h.ForwardedHops
	}
	return c.updateSingleton(ctx, "x:Http/set", patch)
}

// BanPeriods are how long Stalwart's bans last. Nil means permanent.
type BanPeriods struct {
	Auth, Abuse, Scan *time.Duration
}

// BanPeriods reads the authentication, abuse and scan ban periods.
func (c *Client) BanPeriods(ctx context.Context) (BanPeriods, error) {
	var raw struct {
		Auth  *int64 `json:"authBanPeriod"`
		Abuse *int64 `json:"abuseBanPeriod"`
		Scan  *int64 `json:"scanBanPeriod"`
	}
	if err := c.getSingleton(ctx, "x:Security/get", &raw); err != nil {
		return BanPeriods{}, err
	}
	ms := func(v *int64) *time.Duration {
		if v == nil {
			return nil
		}
		d := time.Duration(*v) * time.Millisecond
		return &d
	}
	return BanPeriods{Auth: ms(raw.Auth), Abuse: ms(raw.Abuse), Scan: ms(raw.Scan)}, nil
}

// SetBanPeriods sets the authentication, abuse and scan ban periods to d.
// The loiter ban is left alone.
func (c *Client) SetBanPeriods(ctx context.Context, d time.Duration) error {
	ms := d.Milliseconds()
	return c.updateSingleton(ctx, "x:Security/set", map[string]any{
		"authBanPeriod": ms, "abuseBanPeriod": ms, "scanBanPeriod": ms,
	})
}

// Listener is one network listener.
type Listener struct {
	ID       string
	Name     string
	Protocol string
	Bind     []netip.AddrPort
	// ProxyNetworks are the listener's own PROXY protocol networks.
	ProxyNetworks []string
}

// Listeners lists the network listeners. An address CSM cannot read is an
// error, because the caller decides whether a listener is reachable from
// outside.
func (c *Client) Listeners(ctx context.Context) ([]Listener, error) {
	var raw []struct {
		ID       string          `json:"id"`
		Name     string          `json:"name"`
		Protocol string          `json:"protocol"`
		Bind     map[string]bool `json:"bind"`
		Proxy    map[string]bool `json:"overrideProxyTrustedNetworks"`
	}
	const method = "x:NetworkListener/get"
	if err := c.get(ctx, method, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]Listener, 0, len(raw))
	for _, r := range raw {
		l := Listener{ID: r.ID, Name: r.Name, Protocol: r.Protocol, ProxyNetworks: setKeys(r.Proxy)}
		for _, b := range setKeys(r.Bind) {
			ap, err := netip.ParseAddrPort(b)
			if err != nil {
				return nil, fmt.Errorf("stalwart %s: listener %q binds %q, not an address and port", method, Redact(r.Name, c.user, c.password), Redact(b, c.user, c.password))
			}
			l.Bind = append(l.Bind, ap)
		}
		sort.Slice(l.Bind, func(i, j int) bool { return l.Bind[i].Compare(l.Bind[j]) < 0 })
		out = append(out, l)
	}
	return out, nil
}

// ProxyTrustedNetworks reads the server-wide PROXY protocol networks.
func (c *Client) ProxyTrustedNetworks(ctx context.Context) ([]string, error) {
	var raw struct {
		Networks map[string]bool `json:"proxyTrustedNetworks"`
	}
	if err := c.getSingleton(ctx, "x:SystemSettings/get", &raw); err != nil {
		return nil, err
	}
	return setKeys(raw.Networks), nil
}

// ReloadSettings makes Stalwart apply its stored settings and returns the
// warnings it reports.
func (c *Client) ReloadSettings(ctx context.Context) ([]string, error) {
	const method = "x:Action/set"
	out, err := c.set(ctx, method, map[string]any{
		"create": map[string]any{"r": map[string]any{"@type": "ReloadSettings"}},
	})
	if err != nil {
		return nil, err
	}
	var res struct {
		Created map[string]struct {
			Warnings map[string]json.RawMessage `json:"warnings"`
		} `json:"created"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("stalwart %s: unexpected response", method)
	}
	r, ok := res.Created["r"]
	if !ok {
		return nil, fmt.Errorf("stalwart %s: reload was not acknowledged", method)
	}
	warnings := make([]string, 0, len(r.Warnings))
	for k, v := range r.Warnings {
		var s string
		if json.Unmarshal(v, &s) != nil {
			s = string(v)
		}
		warnings = append(warnings, Redact(k+": "+s, c.user, c.password))
	}
	sort.Strings(warnings)
	return warnings, nil
}

// setKeys returns the keys a JMAP set-as-map marks true, sorted.
func setKeys(m map[string]bool) []string {
	var out []string
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
