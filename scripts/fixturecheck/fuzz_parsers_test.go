package main

import (
	"fmt"
	"testing"
)

func FuzzIPv4FixtureLiteral(f *testing.F) {
	for _, seed := range []string{"192.0.2.4", "client=8.8.4.4", "999.888.777.666", "203.0.113.1\x00", "version=1.2.3"} {
		f.Add(seed, uint8(42))
	}
	f.Fuzz(func(t *testing.T, noise string, octet uint8) {
		if !disallowedIPv4([]byte(noise + "\n8.8.4.4\n")) {
			t.Fatal("surrounding data hid a disallowed address")
		}
		for _, prefix := range []string{"192.0.2.", "198.51.100.", "203.0.113."} {
			if disallowedIPv4([]byte(fmt.Sprintf("[%s%d]", prefix, octet))) {
				t.Fatal("documentation address was rejected")
			}
		}
	})
}
