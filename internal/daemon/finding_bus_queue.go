package daemon

import (
	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/broadcast"
)

func (d *Daemon) installFindingBus() {
	bus := broadcast.NewBus(64)
	d.registerQueueSource("events", bus)
	d.findingBus = bus
	alert.FindingBus = bus
}
