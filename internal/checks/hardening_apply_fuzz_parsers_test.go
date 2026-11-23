package checks

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func FuzzHardeningApplyRequest(f *testing.F) {
	for _, seed := range []string{`{"category":"php"}`, `{"category":"ssh","names":["ssh_use_dns"]}`, `{"category":"os","names":null}`, `{"category":"os"}]`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		req, err := ReadHardeningApplyRequest(strings.NewReader(body))
		if err != nil {
			return
		}
		var wire struct {
			Category string
			Names    []string
		}
		if len(body) > hardeningApplyRequestLimit || json.Unmarshal([]byte(body), &wire) != nil || req.Category != wire.Category || !slices.Equal(req.Names, wire.Names) {
			t.Fatal("accepted request changed the selected checks")
		}
		if !slices.Contains(HardeningCategories, req.Category) || len(req.Names) > hardeningApplyMaxNames {
			t.Fatal("invalid category or selection size")
		}
		for _, name := range req.Names {
			if len(name) == 0 || len(name) > 80 || strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
				t.Fatal("accepted invalid identifier")
			}
		}
	})
}

func FuzzHardeningUndoRequest(f *testing.F) {
	for _, seed := range []string{`{"name":"ssh_use_dns"}`, `{"name":"php_expose_82"}`, `{"name":null}`, `{"name":"cp_updates"}]`, `{"name":"../cp_updates"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		req, err := ReadHardeningUndoRequest(strings.NewReader(body))
		if err != nil {
			return
		}
		var wire struct{ Name string }
		if len(body) > hardeningApplyRequestLimit || json.Unmarshal([]byte(body), &wire) != nil || req.Name != wire.Name {
			t.Fatal("accepted request changed the fix name")
		}
		if !knownHardeningFix(req.Name) {
			t.Fatal("accepted a name that is not a known fix")
		}
	})
}
