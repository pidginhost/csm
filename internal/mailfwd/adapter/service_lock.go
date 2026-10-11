package adapter

import (
	"path/filepath"

	"github.com/pidginhost/csm/internal/eximlock"
	"github.com/pidginhost/csm/internal/mailfwd/policy"
)

type lockedEximAdapter struct{ *EximAdapter }

func (a lockedEximAdapter) Apply(cfg policy.Config, ips []string) error {
	return eximlock.With(filepath.Dir(a.badIPsPath), func() error { return a.EximAdapter.Apply(cfg, ips) })
}

func (a lockedEximAdapter) Remove() error {
	return eximlock.With(filepath.Dir(a.badIPsPath), a.EximAdapter.Remove)
}
