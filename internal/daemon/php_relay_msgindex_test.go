package daemon

import (
	"testing"
	"time"
)

func TestMsgIDIndex_PutGet(t *testing.T) {
	idx := newMsgIDIndex(nil, 1024)
	idx.Put("id1", indexEntry{ScriptKey: "s:p", SourceIP: "192.0.2.1", CPUser: "u", At: time.Now()})
	e, ok := idx.Get("id1")
	if !ok || e.ScriptKey != "s:p" {
		t.Fatalf("Get id1 = %+v, ok=%v", e, ok)
	}
}

func TestMsgIDIndex_Has(t *testing.T) {
	idx := newMsgIDIndex(nil, 1024)
	if idx.Has("id1") {
		t.Fatal("empty index must not Has")
	}
	idx.Put("id1", indexEntry{At: time.Now()})
	if !idx.Has("id1") {
		t.Fatal("Has after Put failed")
	}
}

func TestMsgIDIndex_TimeSweep(t *testing.T) {
	idx := newMsgIDIndex(nil, 1024)
	old := time.Now().Add(-5 * time.Hour)
	idx.Put("expired", indexEntry{At: old})
	idx.Put("fresh", indexEntry{At: time.Now()})

	idx.SweepMemory(time.Now().Add(-4 * time.Hour))

	if idx.Has("expired") {
		t.Errorf("expired entry should be swept")
	}
	if !idx.Has("fresh") {
		t.Errorf("fresh entry should remain")
	}
}

func TestMsgIDIndex_Cap(t *testing.T) {
	idx := newMsgIDIndex(nil, 3)
	for _, id := range []string{"a", "b", "c", "d"} {
		idx.Put(id, indexEntry{At: time.Now()})
	}
	if got := idx.Len(); got > 3 {
		t.Errorf("len = %d, expected <= 3", got)
	}
}
