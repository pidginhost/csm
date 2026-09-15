package config

import (
	"fmt"
	"time"
)

const DefaultBrowserSessionLifetime = "24h"
const DefaultBrowserSessionIdleTimeout = "30m"

// BrowserSessionDurations also accepts an un-defaulted configuration, as used
// by embedded callers. Explicit zero durations never disable session expiry.
func (c *Config) BrowserSessionDurations() (time.Duration, time.Duration, error) {
	lifetimeText, idleText := c.WebUI.SessionLifetime, c.WebUI.SessionIdleTimeout
	if lifetimeText == "" {
		lifetimeText = DefaultBrowserSessionLifetime
	}
	if idleText == "" {
		idleText = DefaultBrowserSessionIdleTimeout
	}
	lifetime, err := time.ParseDuration(lifetimeText)
	if err != nil || lifetime < time.Second || lifetime > 30*24*time.Hour {
		return 0, 0, fmt.Errorf("webui.session_lifetime must be between 1s and 720h")
	}
	idle, err := time.ParseDuration(idleText)
	if err != nil || idle < time.Second || idle > lifetime {
		return 0, 0, fmt.Errorf("webui.session_idle_timeout must be between 1s and session_lifetime")
	}
	return lifetime, idle, nil
}
