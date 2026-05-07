package processctx

import "time"

// Materialize walks the PPID chain starting at pid up to MaxParentDepth and
// returns a ProcessContext tree. Returns nil if pid is not in the cache.
// Cycle-safe: tracks visited PIDs.
func (c *Cache) Materialize(pid int) *ProcessContext {
	root, ok := c.Get(pid)
	if !ok {
		return nil
	}
	visited := map[int]bool{root.PID: true}
	head := toContext(root)
	cur := head
	parentPID := root.PPID
	for depth := 1; depth < MaxParentDepth; depth++ {
		if parentPID <= 0 || visited[parentPID] {
			break
		}
		entry, ok := c.Get(parentPID)
		if !ok {
			break
		}
		visited[entry.PID] = true
		cur.Parent = toContext(entry)
		cur = cur.Parent
		parentPID = entry.PPID
	}
	return head
}

func toContext(e processEntry) *ProcessContext {
	var startedAt *time.Time
	if !e.StartedAt.IsZero() {
		t := e.StartedAt
		startedAt = &t
	}
	return &ProcessContext{
		PID:       e.PID,
		PPID:      e.PPID,
		UID:       e.UID,
		User:      e.User,
		Account:   e.Account,
		Comm:      e.Comm,
		Exe:       e.Exe,
		Cmdline:   append([]string(nil), e.Cmdline...),
		StartedAt: startedAt,
	}
}
