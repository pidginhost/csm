package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

const periodEvidence = `{"format_version":1,"d2_revision":"` + d2Revision + `","config_sha256":"` + d2Config + `","proofs":[
 {"bot":"googlebot","kind":"range","prefix":"203.0.113.0/25","from":"2026-09-26T19:00:00Z","to":"2026-09-26T19:30:00Z"},
 {"bot":"bingbot","kind":"range","prefix":"203.0.113.128/25","from":"2026-09-26T19:00:00Z","to":"2026-09-26T19:30:00Z"},
 {"bot":"googlebot","kind":"dns","addr":"192.0.2.60","verdict":"positive","from":"2026-09-26T19:00:00Z","to":"2026-09-26T19:30:00Z"},
 {"bot":"googlebot","kind":"dns","addr":"192.0.2.61","verdict":"negative","from":"2026-09-26T19:00:00Z","to":"2026-09-26T19:30:00Z"},
 {"bot":"googlebot","kind":"dns","addr":"192.0.2.62","verdict":"positive","from":"2026-09-26T19:00:00Z","to":"2026-09-26T19:10:00Z"}]}`

func TestBindingAndBotEvidence(t *testing.T) {
	const google, bing, browser = "Googlebot/2.1 (+http://crawler.example/bot)", "bingbot/2.0", "Mozilla/5.0"
	ua := func(l, agent string) string { return strings.Replace(l, `"Mozilla/5.0"`, `"`+agent+`"`, 1) }
	get := "GET /?p=1 HTTP/1.1"
	lines := []string{
		line("192.0.2.10", "19:00:10", get, "200", ""),
		line("::ffff:192.0.2.10", "19:00:11", get, "200", ""),
		line("2001:db8:1:2::1", "19:00:12", get, "200", ""),
		line("2001:db8:1:2:ffff::9", "19:00:13", get, "200", ""),
		line("2001:db8:1:3::1", "19:00:14", get, "200", ""),
		line("192.0.2.11", "19:00:15", get, "200", ` "203.0.113.5"`),
		line("192.0.2.11", "19:00:16", get, "200", ""),
		line("198.51.100.9", "19:00:17", get, "200", ""),
		line("198.51.100.9", "19:00:18", get, "200", ` "garbage, 192.0.2.12"`),
		line("192.0.2.12", "19:00:19", get, "200", ""),
		line("198.51.100.9", "19:00:20", get, "200", ` "192.0.2.13, 198.51.100.10"`),
		ua(line("203.0.113.5", "19:01:00", get, "200", ""), google),
		ua(line("203.0.113.200", "19:01:01", get, "200", ""), google),
		ua(line("203.0.113.201", "19:01:02", get, "200", ""), bing),
		ua(line("192.0.2.60", "19:01:03", get, "200", ""), google),
		ua(line("192.0.2.61", "19:01:04", get, "200", ""), google),
		ua(line("192.0.2.62", "19:20:00", get, "200", ""), google),
		ua(line("192.0.2.63", "19:01:05", get, "200", ""), google),
		ua(line("192.0.2.64", "19:01:06", get, "200", ""), browser),
		ua(line("::ffff:203.0.113.6", "19:01:07", get, "200", ""), google),
		ua(line("198.51.100.9", "19:01:08", get, "200", ` "203.0.113.7"`), google),
	}
	c := convertLogs(t, []synthLog{{name: "example.com", data: strings.Join(lines, "\n") + "\n"}}, periodEvidence)
	if len(c.records) != len(lines) {
		t.Fatalf("records = %d, want %d", len(c.records), len(lines))
	}
	r := func(n int) crawlreplay.Record { return c.records[n-1] }
	for _, same := range [][2]int{{1, 2}, {3, 4}, {6, 7}, {9, 10}} {
		if r(same[0]).Binding == "" || r(same[0]).Binding != r(same[1]).Binding {
			t.Errorf("lines %d and %d: bindings %q %q, want one binding", same[0], same[1], r(same[0]).Binding, r(same[1]).Binding)
		}
	}
	if r(5).Binding == r(3).Binding || r(5).Binding == "" {
		t.Error("an adjacent IPv6 /64 shares a binding")
	}
	for _, unbound := range []int{8, 11} {
		if r(unbound).Binding != "" {
			t.Errorf("line %d: an unattributed proxied line was bound", unbound)
		}
	}
	for n, want := range map[int][2]string{
		12: {"googlebot", crawlreplay.BotProofRange},
		13: {"googlebot", ""},
		14: {"bingbot", crawlreplay.BotProofRange},
		15: {"googlebot", crawlreplay.BotProofDNS},
		16: {"googlebot", crawlreplay.BotProofNegative},
		17: {"googlebot", ""},
		18: {"googlebot", ""},
		19: {"", ""},
		20: {"googlebot", crawlreplay.BotProofRange},
		21: {"googlebot", crawlreplay.BotProofRange},
	} {
		if got := r(n); got.Bot != want[0] || got.BotProof != want[1] {
			t.Errorf("line %d: bot %q proof %q, want %q %q", n, got.Bot, got.BotProof, want[0], want[1])
		}
	}
	sum := sha256.Sum256([]byte(periodEvidence))
	ref := c.manifest.BotEvidence
	if ref == nil || ref.SHA256 != hex.EncodeToString(sum[:]) || ref.Bytes != int64(len(periodEvidence)) ||
		ref.D2Revision != d2Revision || ref.ConfigSHA256 != d2Config {
		t.Fatalf("manifest bot evidence = %+v", ref)
	}

	without := convertLogs(t, []synthLog{{name: "example.com", data: strings.Join(lines, "\n") + "\n"}}, "")
	for _, rec := range without.records {
		if rec.BotProof != "" {
			t.Fatalf("a claim became %q without evidence", rec.BotProof)
		}
	}
	if without.manifest.BotEvidence != nil {
		t.Fatal("manifest names bot evidence that was not supplied")
	}
}

func TestBotEvidenceIsClosed(t *testing.T) {
	proof := func(fields string) string {
		return `{"format_version":1,"d2_revision":"` + d2Revision + `","config_sha256":"` + d2Config + `","proofs":[{` + fields + `}]}`
	}
	times := `"from":"2026-09-26T19:00:00Z","to":"2026-09-26T19:30:00Z"`
	if _, err := parseBotEvidence([]byte(proof(`"bot":"googlebot","kind":"range","prefix":"203.0.113.0/25",` + times))); err != nil {
		t.Fatalf("valid evidence refused: %v", err)
	}
	for name, doc := range map[string]string{
		"dirty revision":  strings.Replace(proof(`"bot":"googlebot","kind":"range","prefix":"203.0.113.0/25",`+times), d2Revision, "dirty", 1),
		"config digest":   strings.Replace(proof(`"bot":"googlebot","kind":"range","prefix":"203.0.113.0/25",`+times), d2Config, "x", 1),
		"version":         strings.Replace(proof(`"bot":"googlebot","kind":"range","prefix":"203.0.113.0/25",`+times), `"format_version":1`, `"format_version":2`, 1),
		"kind":            proof(`"bot":"googlebot","kind":"list","prefix":"203.0.113.0/25",` + times),
		"range address":   proof(`"bot":"googlebot","kind":"range","prefix":"203.0.113.0/25","addr":"203.0.113.5",` + times),
		"range prefix":    proof(`"bot":"googlebot","kind":"range","prefix":"203.0.113.0/33",` + times),
		"dns prefix":      proof(`"bot":"googlebot","kind":"dns","addr":"192.0.2.60","verdict":"positive","prefix":"192.0.2.0/24",` + times),
		"dns zone":        proof(`"bot":"googlebot","kind":"dns","addr":"fe80::1%eth0","verdict":"positive",` + times),
		"pending verdict": proof(`"bot":"googlebot","kind":"dns","addr":"192.0.2.60","verdict":"pending",` + times),
		"empty interval":  proof(`"bot":"googlebot","kind":"range","prefix":"203.0.113.0/25","from":"2026-09-26T19:00:00Z","to":"2026-09-26T19:00:00Z"`),
		"missing end":     proof(`"bot":"googlebot","kind":"range","prefix":"203.0.113.0/25","from":"2026-09-26T19:00:00Z"`),
		"identity":        proof(`"bot":"Googlebot","kind":"range","prefix":"203.0.113.0/25",` + times),
		"unknown member":  proof(`"bot":"googlebot","kind":"range","prefix":"203.0.113.0/25","source":"operator",` + times),
		"null":            proof(`"bot":"googlebot","kind":"range","prefix":null,` + times),
	} {
		if _, err := parseBotEvidence([]byte(doc)); !errors.Is(err, errBotEvidence) {
			t.Errorf("%s: err = %v, want errBotEvidence", name, err)
		}
	}
}

func TestBotEvidenceTimeBoundaries(t *testing.T) {
	evidence, err := parseBotEvidence([]byte(periodEvidence))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ peer, bot, at, want string }{
		{"203.0.113.5", "googlebot", "18:59:59", ""},
		{"203.0.113.5", "googlebot", "19:00:00", crawlreplay.BotProofRange},
		{"203.0.113.5", "googlebot", "19:30:00", ""},
		{"192.0.2.62", "googlebot", "19:00:00", crawlreplay.BotProofDNS},
		{"192.0.2.62", "googlebot", "19:10:00", ""},
		{"192.0.2.60", "bingbot", "19:01:00", ""},
	} {
		got := evidence.proof(tc.bot, netip.MustParseAddr(tc.peer), time.Unix(unixAt(tc.at), 0))
		if got != tc.want {
			t.Errorf("%+v: proof %q", tc, got)
		}
	}
	conflict := strings.Replace(periodEvidence, `"proofs":[`, `"proofs":[{"bot":"googlebot","kind":"dns","addr":"192.0.2.60","verdict":"negative","from":"2026-09-26T19:00:00Z","to":"2026-09-26T19:30:00Z"},`, 1)
	evidence, err = parseBotEvidence([]byte(conflict))
	if err != nil {
		t.Fatal(err)
	}
	if got := evidence.proof("googlebot", netip.MustParseAddr("192.0.2.60"), time.Unix(unixAt("19:01:00"), 0)); got != "" {
		t.Fatalf("contradictory DNS verdict verified: %q", got)
	}
}
