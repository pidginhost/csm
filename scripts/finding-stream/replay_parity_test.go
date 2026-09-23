package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/responsereplay"
)

// The replay reader decodes recordings with its own copy of the strict
// decoder, because it may import nothing outside the standard library. Both
// must accept and refuse the same finding rows. The one intended difference
// is a zero timestamp: the recording tool refuses it, while replay counts the
// row as unplaceable and leaves it out.
func TestReplayReaderAgreesWithRecordingDecoder(t *testing.T) {
	valid := `{"v":1,"ts":"2026-09-08T10:00:00Z","finding_id":"fid-1","severity":"HIGH","check":"a","message":"m","details":"d","hostname":"h"}`
	with := func(old, repl string) string { return strings.Replace(valid, old, repl, 1) }
	chain := func(parents int) string {
		p := `{"pid":1,"ppid":0,"uid":0}`
		for range parents {
			p = `{"pid":1,"ppid":0,"uid":0,"parent":` + p + `}`
		}
		return with(`"hostname":"h"`, `"hostname":"h","process":`+p)
	}
	cmdline := func(n int) string {
		return with(`"hostname":"h"`, `"hostname":"h","process":{"pid":1,"ppid":0,"uid":0,"cmdline":["`+strings.Repeat(`a","`, n-1)+`a"]}`)
	}
	for name, line := range map[string]string{
		"valid":             valid,
		"duplicate key":     with(`"v":1`, `"v":1,"v":1`),
		"case alias":        with(`"check":"a"`, `"CHECK":"a"`),
		"unknown field":     with(`"v":1`, `"v":1,"extra":1`),
		"nested unknown":    with(`"hostname":"h"`, `"hostname":"h","process":{"pid":1,"ppid":0,"uid":0,"extra":1}`),
		"null":              with(`"details":"d"`, `"details":null`),
		"trailing object":   valid + ` {}`,
		"not an object":     `[1]`,
		"malformed":         `{"v":1,`,
		"version":           with(`"v":1`, `"v":2`),
		"missing version":   with(`"v":1,`, ``),
		"missing time":      with(`"ts":"2026-09-08T10:00:00Z",`, ``),
		"lone surrogate":    with(`"message":"m"`, `"message":"\ud800"`),
		"low surrogate":     with(`"message":"m"`, `"message":"\udc00"`),
		"surrogate pair":    with(`"message":"m"`, `"message":"😀"`),
		"invalid utf8":      with(`"message":"m"`, "\"message\":\"\xff\""),
		"unencodable zone":  with(`"ts":"2026-09-08T10:00:00Z"`, `"ts":"2026-09-08T10:00:00+24:00"`),
		"offset time":       with(`"ts":"2026-09-08T10:00:00Z"`, `"ts":"2026-09-08T13:00:00+03:00"`),
		"nbsp after":        valid + " ",
		"text at limit":     with(`"message":"m"`, `"message":"`+strings.Repeat("x", maxTextBytes)+`"`),
		"text over limit":   with(`"message":"m"`, `"message":"`+strings.Repeat("x", maxTextBytes+1)+`"`),
		"scalar over limit": with(`"check":"a"`, `"check":"`+strings.Repeat("x", maxScalarBytes+1)+`"`),
		"parents at limit":  chain(maxParentDepth),
		"parents over":      chain(maxParentDepth + 1),
		"array at limit":    cmdline(maxArrayItems),
		"array over":        cmdline(maxArrayItems + 1),
		"wrong type":        with(`"v":1`, `"v":"1"`),
	} {
		t.Run(name, func(t *testing.T) {
			_, recordErr := decodeFindingLine([]byte(line))
			path := filepath.Join(t.TempDir(), "row.jsonl")
			if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, replayErr := responsereplay.ReadFindings(path)
			if (recordErr == nil) != (replayErr == nil) {
				t.Fatalf("recording decoder: %v, replay reader: %v", recordErr, replayErr)
			}
		})
	}
	zero := strings.Replace(valid, `"ts":"2026-09-08T10:00:00Z"`, `"ts":"0001-01-01T00:00:00Z"`, 1)
	path := filepath.Join(t.TempDir(), "zero.jsonl")
	if err := os.WriteFile(path, []byte(zero+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, replayErr := responsereplay.ReadFindings(path)
	if _, err := decodeFindingLine([]byte(zero)); !errors.Is(err, errRecordTime) || replayErr != nil || rec.Unstamped != 1 || len(rec.Findings) != 0 {
		t.Fatalf("zero timestamp: recording %v, replay %+v %v", err, rec, replayErr)
	}
}

// The replay tool reads the manifest this tool writes with its own strict
// schema. Every field must read back, unchanged.
func TestReplayReadsTheBundleManifest(t *testing.T) {
	for _, withInventory := range []bool{false, true} {
		f := newJoinFixture(t)
		args := f.args()
		if withInventory {
			inventory := filepath.Join(f.dir, "in", "inventory.json")
			writeInput(t, inventory, encodeLines(t, inputManifest{V: 1, Streams: []inputManifestEntry{
				{Kind: "findings", Availability: "present", SHA256: fileDigest(t, f.findings), Records: 2},
				{Kind: "actions", Availability: "present", SHA256: fileDigest(t, f.actions), Records: 3},
				{Kind: "firewall_audit", Availability: "present", SHA256: fileDigest(t, f.firewall), Records: 2},
				{Kind: "ledger", Availability: "not_recorded"},
			}}))
			args = f.args("--input-manifest", inventory)
		}
		if err := testRun().execute(args, io.Discard); err != nil {
			t.Fatal(err)
		}
		m, digest, err := responsereplay.ReadBundleManifest(f.manifest)
		if err != nil {
			t.Fatalf("replay refused the manifest: %v", err)
		}
		if out, ok := m.FindingsOutput(); !ok || out.SHA256 != fileDigest(t, f.out) || digest != fileDigest(t, f.manifest) {
			t.Fatalf("findings output %+v, manifest digest %s", out, digest)
		}
		written, _ := readManifest(t, f.manifest)
		reread, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var back map[string]any
		if err := json.Unmarshal(reread, &back); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(written, back) {
			t.Fatalf("manifest changed through the replay schema:\nwritten %v\nread    %v", written, back)
		}
	}
}

// The replay tool recognises non-scan blocks by the reasons ApplyBlock
// records; this tool must classify each of them as that path.
func TestReasonKindsCoverReplayNonScanPrefixes(t *testing.T) {
	want := map[string]bool{"challenge_timeout": true, "central_intel": true, "credential_spray": true, "incident": true}
	got := map[string]bool{}
	for _, prefix := range responsereplay.NonScanReasonPrefixes {
		kind := reasonKind(prefix + "x")
		if prefix == "central-intel (locally corroborated)" {
			kind = reasonKind(prefix)
		}
		if !want[kind] {
			t.Errorf("reason %q classifies as %q", prefix, kind)
		}
		got[kind] = true
	}
	if len(got) != len(want) {
		t.Fatalf("non-scan kinds covered: %v", got)
	}
}
