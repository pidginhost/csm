package main

import (
	"fmt"

	"github.com/pidginhost/csm/internal/health"
)

func printWPVerificationHuman(coverage map[string]health.WPVerificationCounts) {
	for _, kind := range []string{"core", "plugins"} {
		counts, ok := coverage[kind]
		if !ok {
			continue
		}
		if counts.Error != "" {
			fmt.Printf("WordPress %s: %s\n", kind, counts.Error)
			continue
		}
		fmt.Printf("WordPress %s: verified=%d modified=%d unverified=%d unknown=%d not_wordpress=%d\n", kind, counts.Verified, counts.Modified, counts.Unverified, counts.Unknown, counts.NotWordPress)
	}
}
