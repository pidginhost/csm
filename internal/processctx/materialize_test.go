package processctx

import "testing"

func TestMaterializeStandalone(t *testing.T) {
	c := newTestCache(8, 0) // ttl=0 disables TTL
	c.Put(processEntry{PID: 1234, PPID: 1, UID: 1001, Comm: "ncat"})
	pc := c.Materialize(1234)
	if pc == nil {
		t.Fatal("nil")
	}
	if pc.PID != 1234 || pc.UID != 1001 {
		t.Errorf("unexpected: %+v", pc)
	}
	if pc.Parent != nil {
		t.Errorf("expected no parent (PID 1 not in cache), got %+v", pc.Parent)
	}
}

func TestMaterializeWalksChain(t *testing.T) {
	c := newTestCache(8, 0)
	c.Put(processEntry{PID: 1, PPID: 0, Comm: "init"})
	c.Put(processEntry{PID: 100, PPID: 1, Comm: "php-fpm"})
	c.Put(processEntry{PID: 200, PPID: 100, Comm: "sh"})
	c.Put(processEntry{PID: 300, PPID: 200, Comm: "perl"})
	c.Put(processEntry{PID: 400, PPID: 300, Comm: "ncat"})
	pc := c.Materialize(400)
	want := []string{"ncat", "perl", "sh", "php-fpm", "init"}
	got := []string{}
	for cur := pc; cur != nil; cur = cur.Parent {
		got = append(got, cur.Comm)
	}
	if len(got) != len(want) {
		t.Fatalf("chain length: want %d, got %d (%v)", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("chain[%d]: want %q got %q", i, w, got[i])
		}
	}
}

func TestMaterializeStopsAtMaxDepth(t *testing.T) {
	c := newTestCache(32, 0)
	prev := 0
	// 10 entries: PIDs 1..10, each parented by previous.
	for i := 1; i <= 10; i++ {
		c.Put(processEntry{PID: i, PPID: prev, Comm: "p"})
		prev = i
	}
	pc := c.Materialize(10)
	depth := 0
	for cur := pc; cur != nil; cur = cur.Parent {
		depth++
	}
	if depth != MaxParentDepth {
		t.Errorf("depth: want %d, got %d", MaxParentDepth, depth)
	}
}

func TestMaterializeMissingIntermediateParent(t *testing.T) {
	c := newTestCache(8, 0)
	c.Put(processEntry{PID: 1, PPID: 0, Comm: "init"})
	// PID 100 missing on purpose.
	c.Put(processEntry{PID: 200, PPID: 100, Comm: "sh"})
	pc := c.Materialize(200)
	if pc == nil || pc.Comm != "sh" {
		t.Fatalf("unexpected root: %+v", pc)
	}
	if pc.Parent != nil {
		t.Errorf("expected chain to stop at missing parent, got %+v", pc.Parent)
	}
}

func TestMaterializeUnknownPIDReturnsNil(t *testing.T) {
	c := newTestCache(8, 0)
	if pc := c.Materialize(9999); pc != nil {
		t.Errorf("expected nil for unknown PID, got %+v", pc)
	}
}

func TestMaterializeBreaksOnPIDCycle(t *testing.T) {
	// Defensive: PIDs are not supposed to cycle, but PID-reuse + a stale
	// PPID could create one. Walker must terminate.
	c := newTestCache(8, 0)
	c.Put(processEntry{PID: 1, PPID: 2})
	c.Put(processEntry{PID: 2, PPID: 1})
	pc := c.Materialize(1)
	depth := 0
	for cur := pc; cur != nil; cur = cur.Parent {
		depth++
		if depth > MaxParentDepth+1 {
			t.Fatalf("walker did not terminate; depth=%d", depth)
		}
	}
}
