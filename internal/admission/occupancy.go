package admission

// TemporaryCapacity is the finite temporary set capacity automatic
// admission works within when the configured temporary limit is zero,
// which leaves manual blocks unlimited (spec 5.6). It is code policy,
// pending the validation gate of spec 5.19.
const TemporaryCapacity = 10000

// AutomaticCapacity is the temporary set capacity automatic admission
// works within under the configured temporary limit: the limit, or
// TemporaryCapacity for zero. A negative limit is invalid; until
// configuration refuses one it reads as zero.
func AutomaticCapacity(limit int) int {
	if limit <= 0 {
		return TemporaryCapacity
	}
	return limit
}

// PartitionOf is the partition an entry admitted on lane occupies; zero
// for an invalid lane.
func PartitionOf(l Lane) Partition {
	switch l {
	case LaneGeneral:
		return PartitionGeneral
	case LaneDirect, LaneCorroborated:
		return PartitionReserved
	}
	return 0
}

// SetOccupancy is the temporary set as automatic admission counts it: the
// configured temporary limit, the entries it can never evict (manual,
// unknown provenance and pending manual work), and the automatic entries
// of each partition.
type SetOccupancy struct {
	Limit             int
	Unclaimed         int
	General, Reserved int
}

// SetSlots is how a SetOccupancy divides the set (spec 5.6).
type SetSlots struct {
	// Capacity is AutomaticCapacity of the limit; Available is what the
	// unclaimed entries leave of it, never below zero.
	Capacity, Available int
	// General and Reserved size the partitions: ceil(Available/5) is
	// reserved and the rest general, as the ceiling splits its lanes.
	General, Reserved int
	// FreeGeneral and FreeReserved are each partition's empty slots,
	// bounded by shared headroom. An overfull partition has none.
	FreeGeneral, FreeReserved int
}

// Slots divides o's set into its partitions and their empty slots.
func (o SetOccupancy) Slots() SetSlots {
	s := SetSlots{Capacity: AutomaticCapacity(o.Limit)}
	s.Available = max(s.Capacity-o.Unclaimed, 0)
	s.Reserved = s.Available / 5
	if s.Available%5 != 0 {
		s.Reserved++
	}
	s.General = s.Available - s.Reserved
	s.FreeGeneral = max(s.General-o.General, 0)
	s.FreeReserved = max(s.Reserved-o.Reserved, 0)
	// Existing occupants keep their partition after a limit or manual change.
	// A partition's target room is also bounded by the shared physical room.
	free := max(s.Available-o.General-o.Reserved, 0)
	s.FreeGeneral = min(s.FreeGeneral, free)
	s.FreeReserved = min(s.FreeReserved, free)
	return s
}

// Free is the empty slots a pick on lane may take: those of the partition
// it would occupy.
func (s SetSlots) Free(l Lane) int {
	switch PartitionOf(l) {
	case PartitionGeneral:
		return s.FreeGeneral
	case PartitionReserved:
		return s.FreeReserved
	}
	return 0
}
