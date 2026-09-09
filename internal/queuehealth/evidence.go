package queuehealth

import "fmt"

// Evidence labels sampled and unavailable measurements so notifications and
// doctor cannot present bytes as events or consumer stalls as event ages.
func (s Status) Evidence() string {
	unit := s.DepthUnit
	if unit == "" {
		unit = "items"
	}
	pending, capacity := fmt.Sprint(s.Depth), fmt.Sprint(s.Capacity)
	if s.DepthUnavailable {
		pending = "unknown"
	}
	if s.CapacityUnavailable {
		capacity = "unknown"
	}
	depth := pending + "/" + capacity
	lag := fmt.Sprintf("lag=%.0fs", s.LagSeconds)
	switch s.LagBasis {
	case "consumer_progress":
		lag = fmt.Sprintf("consumer_stall=%.0fs", s.LagSeconds)
	case "unavailable":
		lag = "lag=unavailable"
	}
	dropped := fmt.Sprintf("dropped=%d", s.DroppedTotal)
	if s.DroppedLowerBound {
		dropped = fmt.Sprintf("dropped>=%d", s.DroppedTotal)
	}
	return fmt.Sprintf("depth=%s %s running=%d %s recent_drops=%d %s processing=%.0fs", depth, unit, s.InFlight, dropped, s.RecentDrops, lag, s.ProcessingSeconds)
}
