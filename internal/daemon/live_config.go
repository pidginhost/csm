package daemon

import "github.com/pidginhost/csm/internal/config"

// liveConfigFn returns an accessor for the live daemon config: the active
// (hot-reloaded) config once one is published, otherwise the startup
// snapshot. Long-lived components that used to capture the startup pointer
// read through it so a reload actually reaches them.
func liveConfigFn(startup *config.Config) func() *config.Config {
	return func() *config.Config {
		if active := config.Active(); active != nil {
			return active
		}
		return startup
	}
}
