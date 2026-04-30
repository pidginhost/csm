package daemon

import (
	"strings"
	"testing"
	"time"
)

func TestMsgIDPattern_AcceptsValid(t *testing.T) {
	cases := []string{"1wHpIU-0000000G8Fo-1FA1", "abc-def-1234567890abcdef"}
	for _, c := range cases {
		if !msgIDPattern.MatchString(c) {
			t.Errorf("expected match for %q", c)
		}
	}
}

func TestMsgIDPattern_RejectsInvalid(t *testing.T) {
	cases := []string{"", "short", "id with space", "id;rm-rf", "id\nnewline", strings.Repeat("a", 64)}
	for _, c := range cases {
		if msgIDPattern.MatchString(c) {
			t.Errorf("expected NO match for %q", c)
		}
	}
}

func TestActionRateLimiter_AllowsThenDenies(t *testing.T) {
	rl := newActionRateLimiter(3)
	if !rl.consumeN(2) {
		t.Fatal("first 2 should consume")
	}
	if !rl.consumeN(1) {
		t.Fatal("up to budget should still consume")
	}
	if rl.consumeN(1) {
		t.Fatal("over budget must deny")
	}
}

func TestActionRateLimiter_RefillsAfterMinute(t *testing.T) {
	rl := newActionRateLimiter(2)
	rl.now = func() time.Time { return time.Unix(0, 0) }
	rl.consumeN(2)
	if rl.consumeN(1) {
		t.Fatal("must be denied at boundary")
	}
	rl.now = func() time.Time { return time.Unix(61, 0) }
	if !rl.consumeN(1) {
		t.Fatal("after 61s the bucket should refill")
	}
}
