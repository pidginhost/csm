package daemon

import (
	"sort"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// subnetSighting is one address of a /24 inside the spray window: when it was
// last seen and the line that last named it.
type subnetSighting struct {
	at  time.Time
	obs alert.Observation
}

// sprayConstituents lists the addresses a subnet spray counted, sorted. A /24
// holds at most 256 addresses, which bounds the list.
func sprayConstituents(ips map[string]subnetSighting) []alert.SprayConstituent {
	out := make([]alert.SprayConstituent, 0, len(ips))
	for ip, s := range ips {
		out = append(out, alert.SprayConstituent{Address: ip, LastSeen: s.at, Observation: s.obs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}
