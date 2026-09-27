package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

const ts = "[26/Sep/2026:19:00:00 +0000]"

func cleanTool() toolRevision {
	return toolRevision{Revision: strings.Repeat("a", 40), GoVersion: "go-test"}
}

type fixture struct {
	dir, salt, inventory, labels, out, volume, manifest string
}

func newFixture(t *testing.T, lines map[string]string, gzipped map[string]bool) fixture {
	t.Helper()
	dir := t.TempDir()
	f := fixture{
		dir: dir, salt: filepath.Join(dir, "salt"), inventory: filepath.Join(dir, "inventory.json"),
		labels: filepath.Join(dir, "labels.json"), out: filepath.Join(dir, "records.jsonl.gz"),
		volume: filepath.Join(dir, "volume.jsonl.gz"), manifest: filepath.Join(dir, "manifest.json"),
	}
	if err := os.WriteFile(f.salt, bytes.Repeat([]byte{0x42}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range lines {
		path := filepath.Join(dir, name)
		data := []byte(body)
		if gzipped[name] {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			if _, err := zw.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			data = buf.Bytes()
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inv := `{"sites":[{"name":"example.com","account":"acct1","aliases":["example.com","www.example.com"],
	  "logs":["` + filepath.Join(dir, "example.com") + `","` + filepath.Join(dir, "example.com-ssl_log.gz") + `"]},
	 {"name":"shop.example","account":"acct2","aliases":["shop.example"],"logs":["` + filepath.Join(dir, "shop.example") + `"]}],
	 "trusted_proxies":["198.51.100.9"],"infrastructure":["192.0.2.200"],"bot_ranges":{"googlebot":["203.0.113.0/24"]}}`
	if err := os.WriteFile(f.inventory, []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}
	labels := `{"labels":[
	 {"site":"example.com","from":"2026-09-26T19:00:00Z","to":"2026-09-26T20:00:00Z","label":"attack","episode":"e1","name_prefixes":["filter_"]},
	 {"site":"example.com","from":"2026-09-26T00:00:00Z","to":"2026-09-27T00:00:00Z","label":"healthy"}]}`
	if err := os.WriteFile(f.labels, []byte(labels), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) args() []string {
	return []string{"convert", "--salt-file", f.salt, "--inventory", f.inventory, "--labels", f.labels,
		"--out", f.out, "--volume-out", f.volume, "--manifest", f.manifest}
}

func defaultLogs() (map[string]string, map[string]bool) {
	plain := strings.Join([]string{
		`192.0.2.10 - - ` + ts + ` "GET /category/?filter_color=red HTTP/1.1" 200 5 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - ` + ts + ` "GET /category/?filter_size=m HTTP/1.1" 200 5 "https://www.example.com/c/" "Mozilla/5.0"`,
		`198.51.100.9 - - ` + ts + ` "GET /shop/?s=ring HTTP/1.1" 200 5 "-" "Mozilla/5.0" "garbage, 192.0.2.11"`,
		`198.51.100.9 - - ` + ts + ` "GET /shop/?s=ring HTTP/1.1" 200 5 "-" "Mozilla/5.0"`,
		`203.0.113.5 - - ` + ts + ` "GET /?p=1 HTTP/1.1" 200 5 "-" "Mozilla/5.0 (compatible; Googlebot/2.1)"`,
		`192.0.2.200 - - ` + ts + ` "GET /status?x=1 HTTP/1.1" 200 5 "-" "probe"`,
		`192.0.2.12 - - ` + ts + ` "GET /style.css HTTP/1.1" 200 5 "-" "Mozilla/5.0"`,
		`not a log line`,
		`192.0.2.13 - - [bad-time] "GET / HTTP/1.1" 200 5`,
		`192.0.2.14 - - ` + ts + ` "GET /` + strings.Repeat("a", 70000) + ` HTTP/1.1" 414 0 "-" "-"`,
	}, "\n") + "\n"
	ssl := `192.0.2.10 - - [26/Sep/2026:19:01:00 +0000] "GET /category/?filter_color=blue HTTP/2" 200 5 "-" "Mozilla/5.0"` + "\r\n"
	shop := `192.0.2.10 - - [26/Sep/2026:19:02:00 +0000] "GET /category/?filter_color=red HTTP/1.1" 500 5 "-" "Mozilla/5.0"` + "\n"
	return map[string]string{"example.com": plain, "example.com-ssl_log.gz": ssl, "shop.example": shop},
		map[string]bool{"example.com-ssl_log.gz": true}
}

func readGz(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func convertOK(t *testing.T, f fixture) ([]crawlreplay.Record, []crawlreplay.Volume, manifest) {
	t.Helper()
	var out bytes.Buffer
	if err := run(f.args(), &out, cleanTool); err != nil {
		t.Fatalf("convert: %v", err)
	}
	for _, want := range []string{"lines: 12\n", "records: 9\n", "ns/line: ", "platform: "} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("summary lacks %q: %s", want, out.String())
		}
	}
	var recs []crawlreplay.Record
	if err := crawlreplay.ReadRecords(bytes.NewReader(readGz(t, f.out)), func(r crawlreplay.Record) error {
		recs = append(recs, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var vols []crawlreplay.Volume
	if err := crawlreplay.ReadVolume(bytes.NewReader(readGz(t, f.volume)), func(v crawlreplay.Volume) error {
		vols = append(vols, v)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var m manifest
	raw, err := os.ReadFile(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return recs, vols, m
}

func TestConvertWritesNoRawIdentity(t *testing.T) {
	logs, gz := defaultLogs()
	f := newFixture(t, logs, gz)
	convertOK(t, f)
	for _, path := range []string{f.out, f.volume} {
		body := string(readGz(t, path))
		for _, raw := range []string{"example.com", "shop.example", "192.0.2", "198.51.100", "203.0.113", "filter_", "category", "Mozilla", "acct1", "ring"} {
			if strings.Contains(body, raw) {
				t.Fatalf("%s leaks %q", filepath.Base(path), raw)
			}
		}
	}
	m, err := os.ReadFile(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"example.com", "acct1", f.dir} {
		if strings.Contains(string(m), raw) {
			t.Fatalf("manifest leaks %q", raw)
		}
	}
}

func TestConvertPseudonymsJoinFindingStreams(t *testing.T) {
	logs, gz := defaultLogs()
	recs, _, _ := convertOK(t, newFixture(t, logs, gz))
	// The same salt maps these names to these pseudonyms in scripts/finding-stream.
	if recs[0].Site != "dom-a01dff.example" || recs[0].Account != "acct-7044eb" {
		t.Fatalf("site/account pseudonyms %s %s do not match finding-stream", recs[0].Site, recs[0].Account)
	}
	if recs[len(recs)-1].Site != "dom-dcef08.example" {
		t.Fatalf("second site pseudonym %s", recs[len(recs)-1].Site)
	}
}

func TestConvertRecordsKeepEqualityHierarchyAndAttribution(t *testing.T) {
	logs, gz := defaultLogs()
	recs, _, m := convertOK(t, newFixture(t, logs, gz))
	if len(recs) != 9 {
		t.Fatalf("records = %d, want 8 for the first site and 1 for the second", len(recs))
	}
	red, size, proxied, lost, bot, infra, static, blue := recs[0], recs[1], recs[2], recs[3], recs[4], recs[5], recs[6], recs[7]
	if red.Binding == "" || red.Binding != size.Binding || red.Binding != blue.Binding {
		t.Fatal("one client must keep one binding across lines and files")
	}
	if red.L2 != size.L2 || red.L2 != blue.L2 || red.L1 == size.L1 || red.L1 != blue.L1 {
		t.Fatalf("hierarchy lost: %+v %+v %+v", red, size, blue)
	}
	if red.Class != crawlreplay.ClassExpensive || static.Class != crawlreplay.ClassOther || static.L1 != "" {
		t.Fatal("classes wrong")
	}
	if size.Referer != crawlreplay.RefSameSite || red.Referer != crawlreplay.RefNone {
		t.Fatal("Referer classes wrong")
	}
	if proxied.Binding == "" || proxied.Binding == red.Binding || lost.Binding != "" {
		t.Fatalf("trusted proxy attribution wrong: %+v %+v", proxied, lost)
	}
	if bot.Bot != "googlebot" || !bot.BotRange || !infra.Infra || red.Bot != "" {
		t.Fatalf("bot/infrastructure labels wrong: %+v %+v", bot, infra)
	}
	if red.Label != crawlreplay.LabelAttack || red.Episode != "e-f4120e75fd2f006b" || proxied.Label != crawlreplay.LabelHealthy {
		t.Fatalf("labels wrong: %+v %+v", red, proxied)
	}
	if blue.File != 1 || blue.Seq != 11 || red.Seq != 1 {
		t.Fatalf("logged order lost: file %d seq %d/%d", blue.File, blue.Seq, red.Seq)
	}
	s := m.Sites[0]
	if s.Lines != 11 || s.Oversized != 1 || s.Rejected != 1 || s.TimeInvalid != 1 || s.AttributionLoss != 1 ||
		s.Infrastructure != 1 || s.Records != 8 || s.Labels["attack"] != 3 {
		t.Fatalf("coverage = %+v", s)
	}
	if len(s.Coverage) != 1 || s.Coverage[0].To-s.Coverage[0].From != 1 {
		t.Fatalf("coverage span = %+v", s.Coverage)
	}
}

func TestConvertManifestMatchesOutputs(t *testing.T) {
	logs, gz := defaultLogs()
	f := newFixture(t, logs, gz)
	_, vols, m := convertOK(t, f)
	for _, o := range m.Outputs {
		path := map[string]string{"records": f.out, "volume": f.volume}[o.Kind]
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != o.SHA256 || int64(len(raw)) != o.Bytes {
			t.Fatalf("%s digest mismatch", o.Kind)
		}
	}
	if len(m.Inputs) != 3 || m.Inputs[1].Ordinal != 1 || m.StreamVersion != crawlreplay.StreamVersion {
		t.Fatalf("inputs = %+v", m.Inputs)
	}
	var lines int64
	for _, v := range vols {
		lines += v.Lines
	}
	if lines != 9 {
		t.Fatalf("volume lines = %d, want every timed line (9)", lines)
	}
}

func TestConvertIsDeterministic(t *testing.T) {
	logs, gz := defaultLogs()
	a, b := newFixture(t, logs, gz), newFixture(t, logs, gz)
	recA, _, _ := convertOK(t, a)
	recB, _, _ := convertOK(t, b)
	if len(recA) != len(recB) {
		t.Fatal("record counts differ")
	}
	for i := range recA {
		if recA[i] != recB[i] {
			t.Fatalf("record %d differs between runs with one salt", i)
		}
	}
}

func TestConvertRefusalsWriteNothing(t *testing.T) {
	logs, gz := defaultLogs()
	f := newFixture(t, logs, gz)
	if err := os.WriteFile(f.volume, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(f.args(), io.Discard, cleanTool); !errors.Is(err, errOutputs) {
		t.Fatalf("existing output: %v", err)
	}
	os.Remove(f.volume)
	if err := run(f.args(), io.Discard, func() toolRevision { return toolRevision{Dirty: true} }); !errors.Is(err, errDirtyBuild) {
		t.Fatalf("dirty build: %v", err)
	}
	os.Remove(filepath.Join(f.dir, "shop.example"))
	if err := run(f.args(), io.Discard, cleanTool); !errors.Is(err, errInput) {
		t.Fatalf("missing log: %v", err)
	}
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".domlog-stream-") || e.Name() == "records.jsonl.gz" || e.Name() == "manifest.json" {
			t.Fatalf("refusal left %s", e.Name())
		}
	}
}

func TestInventoryAndLabelValidation(t *testing.T) {
	for name, inv := range map[string]string{
		"no sites":       `{"sites":[]}`,
		"upper name":     `{"sites":[{"name":"Example.com","account":"a","aliases":["Example.com"],"logs":["x"]}]}`,
		"alias missing":  `{"sites":[{"name":"example.com","account":"a","aliases":["www.example.com"],"logs":["x"]}]}`,
		"duplicate log":  `{"sites":[{"name":"a.example","account":"a","aliases":["a.example"],"logs":["x"]},{"name":"b.example","account":"b","aliases":["b.example"],"logs":["x"]}]}`,
		"bad proxy":      `{"sites":[{"name":"a.example","account":"a","aliases":["a.example"],"logs":["x"]}],"trusted_proxies":["not-an-ip"]}`,
		"unknown field":  `{"sites":[{"name":"a.example","account":"a","aliases":["a.example"],"logs":["x"],"path":"/home"}]}`,
		"bad bot name":   `{"sites":[{"name":"a.example","account":"a","aliases":["a.example"],"logs":["x"]}],"bot_ranges":{"Googlebot":["203.0.113.0/24"]}}`,
		"zoned infra ip": `{"sites":[{"name":"a.example","account":"a","aliases":["a.example"],"logs":["x"]}],"infrastructure":["2001:db8::1%eth0"]}`,
	} {
		if _, err := parseInventory([]byte(inv)); !errors.Is(err, errInventory) {
			t.Errorf("%s: %v, want errInventory", name, err)
		}
	}
	inv, err := parseInventory([]byte(`{"sites":[{"name":"a.example","account":"a","aliases":["a.example"],"logs":["x"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, lf := range map[string]string{
		"unknown site":    `{"labels":[{"site":"b.example","from":"2026-09-26T00:00:00Z","to":"2026-09-27T00:00:00Z","label":"healthy"}]}`,
		"reversed range":  `{"labels":[{"site":"a.example","from":"2026-09-27T00:00:00Z","to":"2026-09-26T00:00:00Z","label":"healthy"}]}`,
		"attack no ep":    `{"labels":[{"site":"a.example","from":"2026-09-26T00:00:00Z","to":"2026-09-27T00:00:00Z","label":"attack"}]}`,
		"healthy with ep": `{"labels":[{"site":"a.example","from":"2026-09-26T00:00:00Z","to":"2026-09-27T00:00:00Z","label":"healthy","episode":"x"}]}`,
		"upper prefix":    `{"labels":[{"site":"a.example","from":"2026-09-26T00:00:00Z","to":"2026-09-27T00:00:00Z","label":"healthy","name_prefixes":["Filter_"]}]}`,
		"bad label":       `{"labels":[{"site":"a.example","from":"2026-09-26T00:00:00Z","to":"2026-09-27T00:00:00Z","label":"bot"}]}`,
	} {
		if _, err := parseLabels([]byte(lf), inv); !errors.Is(err, errLabels) {
			t.Errorf("%s: %v, want errLabels", name, err)
		}
	}
}

func TestSaltMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "salt")
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateSalt(path); !errors.Is(err, errSaltUnsafe) {
		t.Fatalf("world-readable salt: %v", err)
	}
	created := filepath.Join(dir, "new", "salt")
	salt, err := loadOrCreateSalt(created)
	if err != nil || len(salt) != 32 {
		t.Fatalf("create: %v", err)
	}
	info, err := os.Stat(created)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("created salt mode %v %v", info.Mode(), err)
	}
}

func TestConvertEpisodeNamesArePseudonyms(t *testing.T) {
	logs, gz := defaultLogs()
	f := newFixture(t, logs, gz)
	labels, err := os.ReadFile(f.labels)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.labels, bytes.ReplaceAll(labels, []byte(`"e1"`), []byte(`"acct1"`)), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err = run(f.args(), &stdout, cleanTool); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{readGz(t, f.out), readGz(t, f.volume), manifest, stdout.Bytes()} {
		for _, raw := range []string{"acct1", "example.com", "shop.example", f.dir, "filter_", "Mozilla", "192.0.2.10"} {
			if bytes.Contains(body, []byte(raw)) {
				t.Fatalf("output leaks synthetic marker %q", raw)
			}
		}
	}
	var episodes []string
	if err = crawlreplay.ReadRecords(bytes.NewReader(readGz(t, f.out)), func(r crawlreplay.Record) error {
		if r.Episode != "" {
			episodes = append(episodes, r.Episode)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(episodes) != 3 || episodes[0] != episodes[1] || episodes[0] != episodes[2] {
		t.Fatalf("episode equality lost: %v", episodes)
	}
}

type failingPrivateWriter struct{}

func (failingPrivateWriter) Write([]byte) (int, error) {
	return 0, &os.PathError{Op: "write", Path: "/private/example.com/acct1", Err: os.ErrPermission}
}

func TestConvertWriteFailureDoesNotLeak(t *testing.T) {
	logs, gz := defaultLogs()
	f := newFixture(t, logs, gz)
	data, err := os.ReadFile(f.inventory)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := parseInventory(data)
	if err != nil {
		t.Fatal(err)
	}
	c := converter{inv: inv, ps: pseudonyms{salt: bytes.Repeat([]byte{0x42}, 32)}, open: openLog}
	_, _, _, err = c.convertSite(inv.Sites[0], failingPrivateWriter{})
	if !errors.Is(err, errOutputs) || strings.Contains(err.Error(), "example.com") {
		t.Fatalf("write refusal = %v, want fixed output error", err)
	}
}

func TestManifestCountsVolumeRows(t *testing.T) {
	logs, gz := defaultLogs()
	recs, vols, m := convertOK(t, newFixture(t, logs, gz))
	for _, o := range m.Outputs {
		want := len(recs)
		if o.Kind == "volume" {
			want = len(vols)
		}
		if o.Rows != int64(want) {
			t.Fatalf("%s rows = %d, want %d", o.Kind, o.Rows, want)
		}
	}
}

func TestInventoryRejectsTrailingJSON(t *testing.T) {
	valid := `{"sites":[{"name":"a.example","account":"a","aliases":["a.example"],"logs":["x"]}]}`
	for _, suffix := range []string{"]", "}", "null", "{}"} {
		if _, err := parseInventory([]byte(valid + suffix)); !errors.Is(err, errInventory) {
			t.Fatalf("trailing JSON %q accepted: %v", suffix, err)
		}
	}
}

func TestPublishFailureClosesAllStages(t *testing.T) {
	dir := t.TempDir()
	a, err := newStaged(filepath.Join(dir, "a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := newStaged(filepath.Join(dir, "b"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := newStaged(filepath.Join(dir, "c"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(b.final, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = publish(a, b, c); !errors.Is(err, errOutputs) {
		t.Fatalf("publish = %v", err)
	}
	for _, s := range []*staged{a, b, c} {
		if _, err = s.file.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("stage remains open: %v", err)
		}
		if _, err = os.Stat(s.file.Name()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temporary remains: %v", err)
		}
	}
	data, err := os.ReadFile(b.final)
	if err != nil || string(data) != "existing" {
		t.Fatal("existing output changed")
	}
	if _, err = os.Stat(a.final); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial publication remains")
	}
}
