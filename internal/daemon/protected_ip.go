package daemon

import (
	"errors"

	"github.com/pidginhost/csm/internal/firewall"
)

func isProtectedIPRefusal(err error) bool {
	return errors.Is(err, firewall.ErrIPProtected)
}
