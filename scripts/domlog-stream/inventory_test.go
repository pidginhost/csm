package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestInventoryDNSNameLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		ok   bool
	}{
		{"maximum", 253, true},
		{"too long", 254, false},
	} {
		prefix, suffix := strings.Repeat(strings.Repeat("a", 63)+".", 3), ".example"
		name := prefix + strings.Repeat("b", tc.size-len(prefix)-len(suffix)) + suffix
		for _, field := range []string{"site", "alias"} {
			t.Run(tc.name+"/"+field, func(t *testing.T) {
				site := inventorySite{Name: "example.com", Account: "acct1", Aliases: []string{"example.com"}, Logs: []string{"example.log"}}
				if field == "site" {
					site.Name, site.Aliases = name, []string{name}
				} else {
					site.Aliases = append(site.Aliases, name)
				}
				data, err := json.Marshal(inventory{Sites: []inventorySite{site}})
				if err != nil {
					t.Fatal(err)
				}
				_, err = parseInventory(data)
				if tc.ok && err != nil {
					t.Fatalf("valid DNS name rejected: %v", err)
				}
				if !tc.ok && !errors.Is(err, errInventory) {
					t.Fatalf("oversized DNS name accepted: %v", err)
				}
			})
		}
	}
}
