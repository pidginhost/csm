package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

var updateGolden = flag.Bool("update", false, "rewrite the round-trip golden bundle")

const roundTrip = "testdata/roundtrip"

// findingRow is a synthetic finding-stream row for account acct1 at
// 19:12:30 under the test salt; scripts/finding-stream pins its pseudonyms
// in TestCrawlStreamPseudonymVectors.
const findingRow = `{"v":1,"ts":"2026-09-26T19:12:30Z","severity":"high","check":"lve_limit","message":"limit reached","tenant_id":"acct-7044eb","domain":"dom-a01dff.example"}`

// TestConverterCalibratorRoundTrip converts the synthetic round-trip logs
// through the real entry point and requires the golden bundle byte for
// byte. crawl-calibrate's test of the same name replays that bundle, so
// the two commands are held to one contract.
func TestConverterCalibratorRoundTrip(t *testing.T) {
	out := t.TempDir()
	salt := filepath.Join(out, "salt")
	if err := os.WriteFile(salt, bytes.Repeat([]byte{0x42}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"convert", "--salt-file", salt, "--registry", filepath.Join(out, "registry.json"), "--new-registry",
		"--inventory", roundTrip + "/inventory.json", "--labels", roundTrip + "/labels.json", "--bot-evidence", roundTrip + "/bots.json",
		"--out", filepath.Join(out, "records.jsonl"), "--volume-out", filepath.Join(out, "volume.jsonl"), "--manifest", filepath.Join(out, "manifest.json")}
	if err := run(args, &bytes.Buffer{}, testEnv()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"records.jsonl", "volume.jsonl", "manifest.json"} {
		got, golden := mustRead(t, filepath.Join(out, name)), filepath.Join(roundTrip, name)
		if *updateGolden {
			if err := os.WriteFile(golden, got, 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if !bytes.Equal(got, mustRead(t, golden)) {
			t.Fatalf("%s differs from the golden bundle crawl-calibrate replays; rerun with -update only for an intended contract change", name)
		}
		for _, raw := range []string{"example.com", "shop.example", "acct1", "acct2", "192.0.2", "198.51.100", "203.0.113",
			"filter_", "page", "ring", "Mozilla", "Googlebot", "malformed", "testdata"} {
			if bytes.Contains(got, []byte(raw)) {
				t.Fatalf("%s leaks %q", name, raw)
			}
		}
	}
	m, err := crawlreplay.DecodeManifest(mustRead(t, filepath.Join(out, "manifest.json")))
	if err != nil {
		t.Fatal(err)
	}
	if m.Sites[0].Site != "dom-a01dff.example" || m.Sites[0].Account != "acct-7044eb" || m.Sites[1].Site != "dom-dcef08.example" {
		t.Fatalf("site/account pseudonyms %+v differ from finding-stream's", m.Sites)
	}
	var finding struct {
		TS       time.Time `json:"ts"`
		TenantID string    `json:"tenant_id"`
	}
	if err = json.Unmarshal([]byte(findingRow), &finding); err != nil {
		t.Fatal(err)
	}
	joined := 0
	if err = crawlreplay.ReadRecords(bytes.NewReader(mustRead(t, filepath.Join(out, "records.jsonl"))), func(r crawlreplay.Record) error {
		if r.Account == finding.TenantID && r.T/60 == finding.TS.Unix()/60 {
			joined++
			if r.Site != m.Sites[0].Site {
				t.Errorf("finding joined a record of %s", r.Site)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Minute 19:12 holds two background requests, six attack requests and
	// one infrastructure probe.
	if joined != 9 {
		t.Fatalf("finding row joined %d records on account and minute, want 9", joined)
	}
}
