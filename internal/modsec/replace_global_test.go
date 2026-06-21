package modsec

import (
	"sync"
	"testing"
)

// A populated registry must never be replaced by an empty/nil one: the vendor
// rule tree is transiently empty during cPanel's modsec_assemble rewrite and
// during a boot-time web-server mis-detection window. Dropping to empty would
// discard known pass and deny actions until the next successful refresh.

func TestReplaceGlobal_KeepsHealthyWhenNewEmpty(t *testing.T) {
	t.Cleanup(ResetGlobalForTest)
	healthy := &Registry{actions: map[int]string{210710: "pass", 949110: "deny"}}
	SetGlobal(healthy)

	if ReplaceGlobal(&Registry{actions: map[int]string{}}) {
		t.Fatal("installed an empty registry over a healthy one")
	}
	if Global() != healthy {
		t.Fatal("previous healthy registry was not kept")
	}
}

func TestReplaceGlobal_KeepsHealthyWhenNewNil(t *testing.T) {
	t.Cleanup(ResetGlobalForTest)
	healthy := &Registry{actions: map[int]string{210710: "pass"}}
	SetGlobal(healthy)

	if ReplaceGlobal(nil) {
		t.Fatal("installed nil over a healthy registry")
	}
	if Global() != healthy {
		t.Fatal("previous healthy registry was not kept")
	}
}

func TestReplaceGlobal_InstallsWhenPreviousNil(t *testing.T) {
	t.Cleanup(ResetGlobalForTest)
	ResetGlobalForTest()
	empty := &Registry{actions: map[int]string{}}

	if !ReplaceGlobal(empty) {
		t.Fatal("refused to install the first registry even though none existed")
	}
	if Global() != empty {
		t.Fatal("first registry not installed")
	}
}

func TestReplaceGlobal_InstallsWhenPreviousEmpty(t *testing.T) {
	t.Cleanup(ResetGlobalForTest)
	SetGlobal(&Registry{actions: map[int]string{}})
	healthy := &Registry{actions: map[int]string{210710: "pass"}}

	if !ReplaceGlobal(healthy) {
		t.Fatal("refused to replace an empty registry with a healthy one")
	}
	if Global() != healthy {
		t.Fatal("healthy registry not installed over empty")
	}
}

func TestReplaceGlobal_InstallsWhenNewNonEmpty(t *testing.T) {
	t.Cleanup(ResetGlobalForTest)
	SetGlobal(&Registry{actions: map[int]string{1: "deny"}})
	newer := &Registry{actions: map[int]string{210710: "pass", 949110: "deny"}}

	if !ReplaceGlobal(newer) {
		t.Fatal("refused to install a non-empty registry")
	}
	if Global() != newer {
		t.Fatal("newer registry not installed")
	}
}

func TestReplaceGlobal_ConcurrentEmptyCannotBlankHealthy(t *testing.T) {
	t.Cleanup(ResetGlobalForTest)

	for i := 0; i < 200; i++ {
		ResetGlobalForTest()
		healthy := &Registry{actions: map[int]string{i + 1: "deny"}}
		empty := &Registry{actions: map[int]string{}}

		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			ReplaceGlobal(empty)
		}()
		go func() {
			defer wg.Done()
			<-start
			ReplaceGlobal(healthy)
		}()
		close(start)
		wg.Wait()

		got := Global()
		if got == nil || got.Len() == 0 {
			t.Fatalf("iteration %d left registry empty after concurrent healthy refresh", i)
		}
	}
}
