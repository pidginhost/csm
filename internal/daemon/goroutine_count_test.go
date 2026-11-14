package daemon

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// goroutinesRunning counts live goroutines with a frame whose function name
// contains frag.
func goroutinesRunning(frag string) int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			count := 0
			for _, g := range strings.Split(string(buf[:n]), "\n\n") {
				if strings.Contains(g, frag) {
					count++
				}
			}
			return count
		}
		buf = make([]byte, 2*len(buf))
	}
}

// waitGoroutines fails the test unless exactly want goroutines come to run
// frag. Starting and stopping a goroutine is asynchronous, so it polls.
func waitGoroutines(t *testing.T, frag string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := goroutinesRunning(frag)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines running %s = %d, want %d", frag, got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
