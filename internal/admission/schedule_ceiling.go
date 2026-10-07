package admission

import "sort"

// CeilingHold preserves the fair turn of a charged head while work with no
// ceiling demand borrows the lane. Each lane keeps at most one such head.
// Its credits are separate from Ring.Held, which promises history or recovery.
type CeilingHold struct {
	ID        CandidateID `json:"id"`
	Scope     string      `json:"scope"`
	Ring      uint8       `json:"ring"`
	Slot      uint8       `json:"slot"`
	ClassSlot uint8       `json:"class_slot"`
	Turn      ScopeTurn   `json:"turn"`
}

func (h *CeilingHold) valid(reserved bool) bool {
	if h == nil {
		return true
	}
	return boundedToken(string(h.ID), 128) && boundedToken(h.Scope, 128) && h.Ring < ringCount && (h.Ring >= ringDirect) == reserved && h.Slot < patternSlots && h.ClassSlot < patternSlots && h.Turn.Severity < patternSlots && h.Turn.Deficit <= MaxMemberCost && h.Turn.Bytes <= MaxHistoryBytes && (reserved || int(classPattern[h.ClassSlot])-1 == int(h.Ring))
}

func (s *scheduler) freeReady(items []ScheduleItem, reserved bool) bool {
	for _, it := range items {
		if it.Ready && it.CeilingCost == 0 && !s.picked[it.ID] && (!reserved || it.Direct || it.Corroborated) {
			return true
		}
	}
	return false
}

func (s *scheduler) held(h **CeilingHold) *ScheduleItem {
	if *h == nil {
		return nil
	}
	for _, it := range s.rings[(*h).Ring].ready[(*h).Scope][severityPattern[(*h).Slot]] {
		if it.ID == (*h).ID && !s.picked[it.ID] {
			return it
		}
	}
	*h = nil
	return nil
}

func (s *scheduler) classPosition(r int) uint8 {
	for k := uint8(0); k < patternSlots; k++ {
		slot := (s.st.ClassSlot + k) % patternSlots
		if int(classPattern[slot])-1 == r {
			return slot
		}
	}
	return s.st.ClassSlot
}

func (s *scheduler) park(h **CeilingHold, it *ScheduleItem, r int, slot uint8) {
	if *h != nil {
		return
	}
	ring := &s.st.Rings[r]
	// #nosec G115 -- r indexes the fixed scheduler rings.
	*h = &CeilingHold{ID: it.ID, Scope: it.Scope, Ring: uint8(r), Slot: slot, ClassSlot: s.classPosition(r), Turn: ring.Scopes[it.Scope]}
	delete(ring.Scopes, it.Scope)
	if ring.Held == it.Scope {
		ring.Held = ""
	}
}

func (s *scheduler) historyHeld(reserved bool) bool {
	first, last := ringC1, ringC3
	if reserved {
		first, last = ringDirect, ringCorroborated
	}
	for r := first; r <= last; r++ {
		if scope := s.st.Rings[r].Held; scope != "" {
			if it, _ := s.head(r, scope); it != nil {
				return true
			}
		}
	}
	return false
}

// serveHeld spends the suspended head's own fair credits; borrowing never
// changes those credits or the independent history promise in the ring.
func (s *scheduler) serveHeld(h **CeilingHold, it *ScheduleItem, bytes, recovery uint64) (*ScheduleItem, bool) {
	hold := *h
	for hold.Turn.Deficit < it.Cost || hold.Turn.Bytes < it.Bytes {
		if hold.Turn.Deficit < MaxMemberCost {
			hold.Turn.Deficit++
		}
		if hold.Turn.Bytes < it.Bytes {
			hold.Turn.Bytes = min(hold.Turn.Bytes+HistoryQuantum, MaxHistoryBytes)
		}
	}
	if uint64(it.Bytes) > bytes || uint64(it.Recovery) > recovery {
		return nil, true
	}
	ring := &s.st.Rings[hold.Ring]
	turn := ring.Scopes[it.Scope]
	turn.Deficit = min(turn.Deficit+hold.Turn.Deficit-it.Cost, MaxMemberCost)
	turn.Bytes = min(turn.Bytes+hold.Turn.Bytes-it.Bytes, MaxHistoryBytes)
	// An independent history hold keeps its severity position. Otherwise
	// this fulfilled fair turn moves to the next severity as usual.
	if ring.Held != it.Scope {
		turn.Severity = (hold.Slot + 1) % patternSlots
	}
	ring.Scopes[it.Scope] = turn
	ring.Last = it.Scope
	if hold.Ring >= ringDirect {
		s.st.NextCorroborated = hold.Ring == ringDirect
	} else {
		s.st.ClassSlot = (hold.ClassSlot + 1) % patternSlots
	}
	*h = nil
	return it, false
}

// borrow serves only zero-demand work. It uses the same fair rotations and
// finite history, recovery and member bounds as ordinary work.
func (s *scheduler) borrow(items []ScheduleItem, reserved bool, bytes, recovery uint64) (*ScheduleItem, Lane, bool) {
	var free []ScheduleItem
	for _, it := range items {
		if it.CeilingCost == 0 && !s.picked[it.ID] {
			free = append(free, it)
		}
	}
	original := s.rings
	s.rings = buildRings(free)
	defer func() { s.rings = original }()
	if reserved {
		order := []int{ringDirect, ringCorroborated}
		if s.st.NextCorroborated {
			order = []int{ringCorroborated, ringDirect}
		}
		for _, r := range order {
			it, blocked := s.serve(r, 0, 0, bytes, recovery)
			if blocked {
				s.st.NextCorroborated = r == ringCorroborated
				return nil, 0, true
			}
			if it != nil {
				s.st.NextCorroborated = r == ringDirect
				lane := LaneDirect
				if r == ringCorroborated {
					lane = LaneCorroborated
				}
				return it, lane, false
			}
		}
	} else {
		for k := uint8(0); k < patternSlots; k++ {
			slot := (s.st.ClassSlot + k) % patternSlots
			it, blocked := s.serve(int(classPattern[slot])-1, 0, 0, bytes, recovery)
			if blocked {
				s.st.ClassSlot = slot
				return nil, 0, true
			}
			if it != nil {
				s.st.ClassSlot = (slot + 1) % patternSlots
				return it, LaneGeneral, false
			}
		}
	}
	return nil, 0, false
}

func (s *scheduler) lane(items []ScheduleItem, reserved bool, budget, fullBudget uint32, bytes, recovery uint64) (*ScheduleItem, Lane, bool) {
	h := &s.st.GeneralHold
	if reserved {
		h = &s.st.ReservedHold
	}
	owed := s.held(h)
	if owed != nil && owed.CeilingCost <= budget && !s.historyHeld(reserved) {
		it, blocked := s.serveHeld(h, owed, bytes, recovery)
		lane := LaneGeneral
		if reserved {
			lane = LaneDirect
			if owed.Corroborated {
				lane = LaneCorroborated
			}
		}
		return it, lane, blocked
	}
	if budget == 0 && owed == nil && s.freeReady(items, reserved) {
		first, last := ringC1, ringC3
		if reserved {
			first, last = ringDirect, ringCorroborated
		}
		// A charged history head keeps its earned promise before borrowing.
		for r := first; r <= last; r++ {
			if it, slot := s.head(r, s.st.Rings[r].Held); it != nil && it.CeilingCost > 0 {
				s.park(h, it, r, slot)
				owed = it
				break
			}
		}
		if owed == nil {
			var order []int
			if reserved {
				order = []int{ringDirect, ringCorroborated}
				if s.st.NextCorroborated {
					order = []int{ringCorroborated, ringDirect}
				}
			} else {
				for k := uint8(0); k < patternSlots; k++ {
					order = append(order, int(classPattern[(s.st.ClassSlot+k)%patternSlots])-1)
				}
			}
			for _, r := range order {
				var scopes []string
				for scope := range s.rings[r].ready {
					scopes = append(scopes, scope)
				}
				sort.Strings(scopes)
				start := sort.SearchStrings(scopes, s.st.Rings[r].Last)
				if start < len(scopes) && scopes[start] == s.st.Rings[r].Last {
					start++
				}
				for visit := 0; visit < len(scopes); visit++ {
					scope := scopes[(start+visit)%len(scopes)]
					if it, slot := s.head(r, scope); it != nil && it.CeilingCost > 0 {
						s.park(h, it, r, slot)
						owed = it
						break
					}
				}
				if owed != nil {
					break
				}
			}
		}
	}
	// A ceiling promise stops other charged work taking its remainder.
	// A head above this call's entire budget does not stop affordable peers.
	if budget == 0 || (owed != nil && owed.CeilingCost <= fullBudget) {
		return s.borrow(items, reserved, bytes, recovery)
	}
	var order []int
	if reserved {
		order = []int{ringDirect, ringCorroborated}
		if s.st.NextCorroborated {
			order = []int{ringCorroborated, ringDirect}
		}
	} else {
		for k := uint8(0); k < patternSlots; k++ {
			order = append(order, int(classPattern[(s.st.ClassSlot+k)%patternSlots])-1)
		}
	}
	original := s.rings
	if owed != nil {
		var rest []ScheduleItem
		for _, it := range items {
			if it.ID != owed.ID {
				rest = append(rest, it)
			}
		}
		s.rings = buildRings(rest)
		defer func() { s.rings = original }()
	}
	for k, r := range order {
		it, blocked := s.serve(r, budget, fullBudget, bytes, recovery)
		if blocked {
			if reserved {
				s.st.NextCorroborated = r == ringCorroborated
			} else {
				s.st.ClassSlot = (s.st.ClassSlot + uint8(k)) % patternSlots
			}
			if it == nil {
				return nil, 0, true
			}
			if !s.freeReady(items, reserved) {
				return nil, 0, true
			}
			_, slot := s.head(r, it.Scope)
			s.park(h, it, r, slot)
			return s.borrow(items, reserved, bytes, recovery)
		}
		if it != nil {
			lane := LaneGeneral
			if reserved {
				lane = LaneDirect
				if r == ringCorroborated {
					lane = LaneCorroborated
				}
				s.st.NextCorroborated = r == ringDirect
			} else {
				s.st.ClassSlot = (s.st.ClassSlot + uint8(k) + 1) % patternSlots
			}
			return it, lane, false
		}
	}
	return s.borrow(items, reserved, bytes, recovery)
}
