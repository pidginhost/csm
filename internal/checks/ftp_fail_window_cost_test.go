package checks

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// A burst spread over many addresses, free to an attacker with an IPv6
// prefix, costs each failure about what a burst from one address does: a
// reader that swept every tracked address per failure would fall behind.
func TestFTPFailWindowCostDoesNotGrowWithSources(t *testing.T) {
	cfg := &config.Config{}
	now := time.Now()
	const n = 20000
	run := func(ip func(int) string) time.Duration {
		w := NewFTPFailWindow()
		start := time.Now()
		for i := range n {
			w.Failure(ip(i), now, now, cfg)
		}
		return time.Since(start)
	}
	one := run(func(int) string { return "2001:db8::1" })
	many := run(func(i int) string { return fmt.Sprintf("2001:db8::%x:%x", i>>16, i&0xffff) })
	if many > 50*one+50*time.Millisecond {
		t.Fatalf("%d failures from distinct addresses took %v, from one address %v", n, many, one)
	}
}
