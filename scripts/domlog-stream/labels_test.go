package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/crawlreplay"
)

func TestLabelsRequireTimeBounds(t *testing.T) {
	inv := &inventory{Sites: []inventorySite{{Name: "example.com"}}}
	for _, field := range []string{"from", "to"} {
		for _, value := range []string{"missing", "null", `"0001-01-01T00:00:00Z"`} {
			t.Run(field+"/"+value, func(t *testing.T) {
				rule := map[string]json.RawMessage{
					"site":  json.RawMessage(`"example.com"`),
					"from":  json.RawMessage(`"2026-09-26T19:00:00Z"`),
					"to":    json.RawMessage(`"2026-09-26T20:00:00Z"`),
					"label": json.RawMessage(`"healthy"`),
				}
				if value == "missing" {
					delete(rule, field)
				} else {
					rule[field] = json.RawMessage(value)
				}
				data, err := json.Marshal(map[string]any{"labels": []any{rule}})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := parseLabels(data, inv); !errors.Is(err, errLabels) {
					t.Fatalf("missing or zero time bound accepted: %v", err)
				}
			})
		}
	}
}

func TestLabelsPreserveTimeBoundaries(t *testing.T) {
	site := inventorySite{Name: "example.com", Account: "acct1", Aliases: []string{"example.com"}}
	inv := &inventory{Sites: []inventorySite{site}}
	labels, err := parseLabels([]byte(`{"labels":[
		{"site":"example.com","from":"2026-09-26T21:00:00.5+02:00","to":"2026-09-26T21:00:01.5+02:00","label":"attack","episode":"e1"},
		{"site":"example.com","from":"2026-09-26T19:00:00Z","to":"2026-09-26T19:00:03Z","label":"healthy"}
	]}`), inv)
	if err != nil {
		t.Fatal(err)
	}
	c := newConverter(inv, labels, pseudonyms{salt: bytes.Repeat([]byte{0x42}, 32)}, testNow)
	for _, tc := range []struct {
		second, label string
	}{
		{"00", crawlreplay.LabelHealthy},
		{"00.499999999", crawlreplay.LabelHealthy},
		{"00.5", crawlreplay.LabelAttack},
		{"01", crawlreplay.LabelAttack},
		{"01.499999999", crawlreplay.LabelAttack},
		{"01.5", crawlreplay.LabelHealthy},
		{"02", crawlreplay.LabelHealthy},
		{"03", ""},
	} {
		t.Run(tc.second, func(t *testing.T) {
			line := `192.0.2.10 - - [26/Sep/2026:19:00:` + tc.second + ` +0000] "GET / HTTP/1.1" 200 5`
			rec, ok := checks.ParseCrawlLogLine(line, site.Aliases)
			if !ok || !rec.TimeOK {
				t.Fatal("fixture did not parse")
			}
			sm := crawlreplay.SiteManifest{Site: c.ps.site(site.Name), Account: c.ps.account(site.Account)}
			row, _ := c.row(site, &sm, rec, 0, 1)
			if row.Label != tc.label {
				t.Fatalf("label = %q, want %q", row.Label, tc.label)
			}
			wantEpisode := ""
			if tc.label == crawlreplay.LabelAttack {
				wantEpisode = "e-f4120e75fd2f006b"
			}
			if row.Episode != wantEpisode {
				t.Fatalf("episode = %q, want %q", row.Episode, wantEpisode)
			}
		})
	}
}

func TestLabelsUseCanonicalASCIINameCase(t *testing.T) {
	site := inventorySite{Name: "example.com", Account: "acct1", Aliases: []string{"example.com"}}
	inv := &inventory{Sites: []inventorySite{site}}
	labels, err := parseLabels([]byte(`{"labels":[
		{"site":"example.com","from":"2026-09-26T19:00:00Z","to":"2026-09-26T20:00:00Z","label":"attack","episode":"e1","name_prefixes":["\u00c4filter_"]}
	]}`), inv)
	if err != nil {
		t.Fatalf("canonical name prefix rejected: %v", err)
	}
	c := newConverter(inv, labels, pseudonyms{salt: bytes.Repeat([]byte{0x42}, 32)}, testNow)
	for _, tc := range []struct {
		name, label string
	}{
		{"%C3%84FILTER_color", crawlreplay.LabelAttack},
		{"%C3%A4FILTER_color", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := `192.0.2.10 - - ` + ts + ` "GET /?` + tc.name + `=red HTTP/1.1" 200 5`
			rec, ok := checks.ParseCrawlLogLine(line, site.Aliases)
			if !ok || rec.TargetInvalid || rec.TargetOverflow {
				t.Fatal("fixture did not parse")
			}
			sm := crawlreplay.SiteManifest{Site: c.ps.site(site.Name), Account: c.ps.account(site.Account)}
			row, _ := c.row(site, &sm, rec, 0, 1)
			if row.Label != tc.label {
				t.Fatalf("label = %q, want %q", row.Label, tc.label)
			}
		})
	}
	data, err := json.Marshal(labelFile{Labels: labels})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseLabels([]byte(strings.ReplaceAll(string(data), "filter_", "FILTER_")), inv); !errors.Is(err, errLabels) {
		t.Fatalf("noncanonical ASCII prefix accepted: %v", err)
	}
}
