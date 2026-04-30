package daemon

import (
	"strings"
	"testing"
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
