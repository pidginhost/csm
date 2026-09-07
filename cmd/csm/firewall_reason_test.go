package main

import (
	"errors"
	"testing"
)

// The reason position swallowed anything, flags included, so an operator who
// assumed flag support got a successful block carrying a garbage reason and no
// warning. It happened to be harmless for deny (permanent is the documented
// default) but only by luck: had the flag meant something, the operator would
// have silently got a different policy than the one they typed.
func TestParseReasonRejectsFlagLikeArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--permanent"},
		{"--comment", "spam incident"},
		{"spam", "--permanent"},
		{"-p"},
	} {
		if _, err := parseReason(args, "default"); err == nil {
			t.Errorf("parseReason(%q) accepted a flag-like argument as reason text", args)
		} else if !errors.Is(err, errReasonLooksLikeFlag) {
			t.Errorf("parseReason(%q) error = %v, want errReasonLooksLikeFlag", args, err)
		}
	}
}

func TestParseReasonAcceptsOrdinaryText(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{nil, "default"},
		{[]string{}, "default"},
		{[]string{"spam"}, "spam"},
		{[]string{"spam", "incident", "2026-09-07"}, "spam incident 2026-09-07"},
		// A lone dash is not a flag, and a negative-looking token mid-sentence
		// must not be mistaken for one.
		{[]string{"scan", "from", "-", "unknown"}, "scan from - unknown"},
	}
	for _, tc := range tests {
		got, err := parseReason(tc.args, "default")
		if err != nil {
			t.Errorf("parseReason(%q) unexpected error: %v", tc.args, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseReason(%q) = %q, want %q", tc.args, got, tc.want)
		}
	}
}

// "csm firewall deny --help" answered "Invalid IP address: --help", which
// tells an operator looking for usage that their shell is broken rather than
// that they asked the wrong way.
func TestIsHelpRequest(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "help"} {
		if !isHelpRequest([]string{arg}) {
			t.Errorf("isHelpRequest(%q) = false, want true", arg)
		}
	}
	for _, args := range [][]string{
		nil,
		{"198.51.100.10"},
		{"198.51.100.10", "help"},
	} {
		if isHelpRequest(args) {
			t.Errorf("isHelpRequest(%q) = true, want false", args)
		}
	}
}
