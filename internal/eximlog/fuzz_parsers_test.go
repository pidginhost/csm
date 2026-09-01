package eximlog

import (
	"net"
	"testing"
)

func FuzzClientIP(f *testing.F) {
	f.Add("H=client [203.0.113.50]:2222 auth failed")
	f.Add("no bracket here")
	f.Add("[1.2.3.4]")
	f.Add("[")
	f.Add("[unclosed bracket")
	f.Add("[][][][]")
	f.Add("authenticator failed for ([203.0.113.9]) [198.51.100.7]:5432: 535")
	f.Add("((( [1.2.3.4]")
	f.Fuzz(func(t *testing.T, line string) {
		got := ClientIP(line)
		if got != "" && net.ParseIP(got) == nil {
			t.Fatalf("ClientIP(%q) = %q, not a valid IP", line, got)
		}
	})
}
