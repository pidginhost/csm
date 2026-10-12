package firewall

import (
	"testing"
	"time"
)

func TestBlockTimeoutNeverOutlivesItsExpiry(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, tc := range []struct {
		left time.Duration
		want time.Duration
		ok   bool
	}{
		{time.Hour, time.Hour, true},
		{time.Millisecond, time.Millisecond, true},
		{1900 * time.Microsecond, time.Millisecond, true},
		{999 * time.Microsecond, 0, false},
		{0, 0, false},
		{-time.Second, 0, false},
	} {
		got, ok := blockTimeout(now.Add(tc.left), now)
		if got != tc.want || ok != tc.ok {
			t.Errorf("blockTimeout(now+%v) = %v, %t; want %v, %t", tc.left, got, ok, tc.want, tc.ok)
		}
	}
	if got, ok := blockTimeout(time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), now); ok || got != 0 {
		t.Fatalf("unrepresentable timeout = %v, %t", got, ok)
	}
}
