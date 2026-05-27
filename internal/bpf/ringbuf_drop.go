package bpf

// dropEventLogStride is how often the drop path logs after the first drop.
// 256 keeps sustained back-pressure visible without flooding the daemon log.
const dropEventLogStride uint64 = 256

func shouldLogDroppedEvent(dropped uint64) bool {
	return dropped == 1 || (dropped > 0 && dropped%dropEventLogStride == 0)
}
