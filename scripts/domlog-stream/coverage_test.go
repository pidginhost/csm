package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

// synthLog is one synthetic log copy; gzipped copies are compressed on disk.
type synthLog struct {
	name string
	data string
	gz   bool
}

type converted struct {
	dir      string
	raw      []byte
	manifest crawlreplay.Manifest
	records  []crawlreplay.Record
	volume   []crawlreplay.Volume
}

// convertLogs converts one site's copies with a 30-minute recording period
// from 19:00 UTC and two trusted proxies, with optional bot evidence.
func convertLogs(t *testing.T, logs []synthLog, evidence string) converted {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for _, l := range logs {
		data := []byte(l.data)
		if l.gz {
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
		path := filepath.Join(dir, l.name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, `"`+path+`"`)
	}
	inv := `{"period":{"from":"2026-09-26T19:00:00Z","to":"2026-09-26T19:30:00Z"},
	 "sites":[{"name":"example.com","account":"acct1","aliases":["example.com"],"logs":[` + strings.Join(paths, ",") + `]}],
	 "trusted_proxies":["198.51.100.9","198.51.100.10"]}`
	f := fixture{dir: dir, salt: filepath.Join(dir, "salt"), inventory: filepath.Join(dir, "inventory.json"),
		out: filepath.Join(dir, "records.jsonl.gz"), volume: filepath.Join(dir, "volume.jsonl.gz"), manifest: filepath.Join(dir, "manifest.json")}
	for path, data := range map[string][]byte{f.salt: bytes.Repeat([]byte{0x42}, 32), f.inventory: []byte(inv)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := append(append([]string{"convert", "--salt-file", f.salt}, registryArgs(filepath.Join(dir, "registry.json"))...), "--inventory", f.inventory,
		"--out", f.out, "--volume-out", f.volume, "--manifest", f.manifest)
	if evidence != "" {
		path := filepath.Join(dir, "bots.json")
		if err := os.WriteFile(path, []byte(evidence), 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--bot-evidence", path)
	}
	if err := run(args, &bytes.Buffer{}, testEnv()); err != nil {
		t.Fatalf("convert: %v", err)
	}
	c := converted{dir: dir}
	var err error
	if c.raw, err = os.ReadFile(f.manifest); err != nil {
		t.Fatal(err)
	}
	if c.manifest, err = crawlreplay.DecodeManifest(c.raw); err != nil {
		t.Fatalf("manifest is not canonical: %v", err)
	}
	if err = crawlreplay.ReadRecords(bytes.NewReader(readGz(t, f.out)), func(r crawlreplay.Record) error {
		c.records = append(c.records, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = crawlreplay.ReadVolume(bytes.NewReader(readGz(t, f.volume)), func(v crawlreplay.Volume) error {
		c.volume = append(c.volume, v)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

// line is one combined-log line at 26 Sep 2026 hh:mm:ss UTC.
func line(peer, hms, request, status, tail string) string {
	return peer + ` - - [26/Sep/2026:` + hms + ` +0000] "` + request + `" ` + status + ` 5 "-" "Mozilla/5.0"` + tail
}

func unixAt(hms string) int64 {
	t, err := time.Parse("2006-01-02 15:04:05", "2026-09-26 "+hms)
	if err != nil {
		panic(err)
	}
	return t.Unix()
}

func TestConvertLossAccounting(t *testing.T) {
	lines := []string{
		line("192.0.2.10", "19:01:10", "GET /c/?filter_a=1 HTTP/1.1", "200", "") + "\r\n",
		"not a log line\n",
		line("192.0.2.11", "19:01:20", "GET /x HTTP/1.1", "200", ` "`+strings.Repeat("A", 70000)+`"`) + "\n",
		`192.0.2.12 - - [bad-time] "GET / HTTP/1.1" 200 5` + "\n",
		`192.0.2.13 - - [01/Jan/2099:00:00:00 +0000] "GET / HTTP/1.1" 200 5` + "\n",
		line("192.0.2.14", "18:59:59", "GET /?p=1 HTTP/1.1", "200", "") + "\n",
		line("192.0.2.15", "19:02:05", "GET ftp://example.com/ HTTP/1.1", "400", "") + "\n",
		line("192.0.2.16", "19:02:06", "GET /"+strings.Repeat("a", 9000)+" HTTP/1.1", "414", "") + "\n",
		line("not-an-ip", "19:02:07", "GET /?p=1 HTTP/1.1", "200", "") + "\n",
		line("fe80::1%eth0", "19:02:08", "GET /?p=1 HTTP/1.1", "200", "") + "\n",
		line("198.51.100.9", "19:03:01", "GET /?p=1 HTTP/1.1", "200", ` "fe80::2%eth0"`) + "\n",
		line("198.51.100.9", "19:03:02", "GET /?p=1 HTTP/1.1", "200", ` "192.0.2.20, 198.51.100.10"`) + "\n",
		line("198.51.100.9", "19:03:03", "GET /?p=1 HTTP/1.1", "200", ` "garbage, 192.0.2.21"`) + "\n",
		line("192.0.2.22", "19:04:00", "GET /?p=1 HTTP/1.1", "200", ""),
	}
	second := line("192.0.2.30", "19:05:00", "GET /?q=1 HTTP/1.1", "200", "") + "\r\n" + "192.0.2.31 - - [26/Sep"
	c := convertLogs(t, []synthLog{{name: "example.com", data: strings.Join(lines, "")}, {name: "example.com-ssl_log.gz", data: second, gz: true}}, "")
	s := c.manifest.Sites[0]
	want := crawlreplay.SiteManifest{
		Site: s.Site, Account: s.Account, Extent: &crawlreplay.Span{From: unixAt("19:01:00") / 60, To: unixAt("19:05:00") / 60},
		Lines: 16, Records: 9, Oversized: 1, Rejected: 1, TimeInvalid: 1, TimeFuture: 1, OutOfPeriod: 1, Incomplete: 2,
		NoTarget: 2, AttributionLoss: 2, InvalidClient: 2, Labels: map[string]int64{"": 9},
		Untimed: []crawlreplay.UntimedLoss{
			{Input: 0, Category: crawlreplay.LossOversized, After: unixAt("19:01:10"), Before: unixAt("18:59:59"), Lines: 1},
			{Input: 0, Category: crawlreplay.LossRejected, After: unixAt("19:01:10"), Before: unixAt("18:59:59"), Lines: 1},
			{Input: 0, Category: crawlreplay.LossTimeInvalid, After: unixAt("19:01:10"), Before: unixAt("18:59:59"), Lines: 1},
			{Input: 0, Category: crawlreplay.LossTimeFuture, After: unixAt("19:01:10"), Before: unixAt("18:59:59"), Lines: 1},
			{Input: 0, Category: crawlreplay.LossIncomplete, After: unixAt("19:03:03"), Lines: 1},
			{Input: 1, Category: crawlreplay.LossIncomplete, After: unixAt("19:05:00"), Lines: 1},
		},
	}
	content := int64(len(strings.Join(lines, "")) + len(second))
	var unplaced int64
	for _, i := range []int{1, 2, 3, 4, 5, 13} {
		unplaced += int64(len(lines[i]))
	}
	unplaced += int64(len("192.0.2.31 - - [26/Sep"))
	want.Bytes, want.UnplacedBytes = content, unplaced
	if !reflect.DeepEqual(s, want) {
		t.Fatalf("site manifest\n got %+v\nwant %+v", s, want)
	}
	var placed int64
	perMinute := map[int64]crawlreplay.Volume{}
	for _, v := range c.volume {
		placed += v.Bytes
		perMinute[v.Minute] = v
	}
	if placed+s.UnplacedBytes != s.Bytes {
		t.Fatalf("placed %d + unplaced %d bytes != %d read", placed, s.UnplacedBytes, s.Bytes)
	}
	m := func(hms string) int64 { return unixAt(hms) / 60 }
	for minute, v := range map[int64]crawlreplay.Volume{
		m("19:01:00"): {Lines: 1, Bytes: int64(len(lines[0]))},
		m("19:02:00"): {Lines: 4, Bytes: int64(len(lines[6]) + len(lines[7]) + len(lines[8]) + len(lines[9])), NoTarget: 2, NoBinding: 2},
		m("19:03:00"): {Lines: 3, Bytes: int64(len(lines[10]) + len(lines[11]) + len(lines[12])), NoBinding: 2},
		m("19:05:00"): {Lines: 1, Bytes: int64(len(line("192.0.2.30", "19:05:00", "GET /?q=1 HTTP/1.1", "200", "")) + 2)},
	} {
		got := perMinute[minute]
		if got.Lines != v.Lines || got.Bytes != v.Bytes || got.NoTarget != v.NoTarget || got.NoBinding != v.NoBinding {
			t.Errorf("minute %d volume = %+v, want %+v", minute, got, v)
		}
	}
	if len(perMinute) != 4 {
		t.Fatalf("volume minutes = %d, want 4", len(perMinute))
	}
	in := c.manifest.Inputs
	if len(in) != 2 || in[0].ContentBytes != int64(len(strings.Join(lines, ""))) || in[0].Bytes != in[0].ContentBytes ||
		in[1].ContentBytes != int64(len(second)) || in[1].Bytes == in[1].ContentBytes {
		t.Fatalf("inputs = %+v", in)
	}
	if !reflect.DeepEqual(in[0].Extent, &crawlreplay.Span{From: m("19:01:00"), To: m("19:03:00")}) ||
		!reflect.DeepEqual(in[1].Extent, &crawlreplay.Span{From: m("19:05:00"), To: m("19:05:00")}) {
		t.Fatalf("input extents = %+v %+v", in[0].Extent, in[1].Extent)
	}
	// 18:59:59 is logged after 19:01:10: the copy shows 71 s of completion
	// delay, out-of-period line included.
	if in[0].DisorderSeconds != 71 || in[1].DisorderSeconds != 0 {
		t.Fatalf("input disorder = %d %d, want 71 0", in[0].DisorderSeconds, in[1].DisorderSeconds)
	}
	bindings := map[int64]string{}
	for _, r := range c.records {
		bindings[r.Seq] = r.Binding
	}
	for seq, bound := range map[int64]bool{1: true, 9: false, 10: false, 11: false, 12: false, 13: true} {
		if (bindings[seq] != "") != bound {
			t.Errorf("line %d binding %q, want bound=%v", seq, bindings[seq], bound)
		}
	}
	if _, ok := bindings[14]; ok {
		t.Fatal("a final line without LF became a request")
	}
}

func TestConvertDisorderAcrossCopies(t *testing.T) {
	logAt := func(hms string) string {
		return line("192.0.2.10", hms, "GET /?p=1 HTTP/1.1", "200", "") + "\n"
	}
	c := convertLogs(t, []synthLog{
		{name: "example.com", data: logAt("19:01:00") + logAt("19:40:00") + "malformed\n" + logAt("19:30:00")},
		{name: "example.com-ssl.gz", data: logAt("19:00:00") + logAt("19:00:20") + "malformed\n" + logAt("19:00:10"), gz: true},
	}, "")
	// Only the first request in the plain copy is in the period. Its loss
	// neighbours still prove 600 s of disorder. The gzip copy is independent.
	for i, want := range []int64{600, 10} {
		if got := c.manifest.Inputs[i].DisorderSeconds; got != want {
			t.Fatalf("copy %d disorder = %d, want %d", i, got, want)
		}
	}
	for _, late := range []int64{599, 600} {
		p := coverageProof(t, c, nil)
		p.LatenessSeconds = late
		_, err := crawlreplay.ValidateBundle(crawlreplay.BundleInput{Manifest: c.manifest, Proof: p,
			Volume:  bytes.NewReader(mustRead(t, filepath.Join(c.dir, "volume.jsonl.gz"))),
			Records: bytes.NewReader(mustRead(t, filepath.Join(c.dir, "records.jsonl.gz")))}, 1, crawlreplay.BundleVisitor{})
		if late < 600 {
			if !errors.Is(err, crawlreplay.ErrProof) {
				t.Fatalf("lateness below out-of-period disorder: %v, want ErrProof", err)
			}
		} else if err != nil {
			t.Fatalf("lateness equal to disorder refused: %v", err)
		}
	}
	for i := range c.manifest.Inputs {
		m := c.manifest
		m.Inputs = slices.Clone(m.Inputs)
		m.Inputs[i].DisorderSeconds--
		raw, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = crawlreplay.DecodeManifest(append(raw, '\n')); !errors.Is(err, crawlreplay.ErrManifest) {
			t.Fatalf("copy %d loss bracket contradicts disorder: %v, want ErrManifest", i, err)
		}
	}
}

func coverageProof(t *testing.T, c converted, rejects []crawlreplay.RejectWaiver) *crawlreplay.CoverageProof {
	t.Helper()
	p := c.manifest.Period
	return &crawlreplay.CoverageProof{FormatVersion: crawlreplay.ProofVersion, ManifestSHA256: c.manifest.Digest(), LatenessSeconds: 60,
		Evidence: []crawlreplay.ProofEvidence{
			{Kind: crawlreplay.EvidenceCollection, SHA256: strings.Repeat("c", 64)},
			{Kind: crawlreplay.EvidenceLiveness, SHA256: strings.Repeat("d", 64)},
			{Kind: crawlreplay.EvidenceLateness, SHA256: strings.Repeat("e", 64)},
			{Kind: crawlreplay.EvidencePreApplication, SHA256: strings.Repeat("f", 64)},
		},
		Sites: []crawlreplay.ProofSite{{Site: c.manifest.Sites[0].Site, Spans: []crawlreplay.Span{p}, Rejects: rejects}}}
}

func validateConverted(t *testing.T, c converted, proof *crawlreplay.CoverageProof) crawlreplay.BundleSite {
	t.Helper()
	sites, err := crawlreplay.ValidateBundle(crawlreplay.BundleInput{Manifest: c.manifest, Proof: proof,
		Volume: bytes.NewReader(mustRead(t, filepath.Join(c.dir, "volume.jsonl.gz"))), Records: bytes.NewReader(mustRead(t, filepath.Join(c.dir, "records.jsonl.gz")))},
		1, crawlreplay.BundleVisitor{})
	if err != nil {
		t.Fatalf("converted bundle refused: %v", err)
	}
	return sites[0]
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCoverageLossNeverTrains converts a crawl with unknown loss, certifies
// the whole period with independent evidence and replays: no window that
// holds a lost request's possible minute is evaluated or learned.
func TestCoverageLossNeverTrains(t *testing.T) {
	var b strings.Builder
	b.WriteString("malformed first line\n")
	for minute := 1; minute <= 28; minute++ {
		for i, sec := range []string{"05", "20", "40"} {
			peer := "192.0.2." + string(rune('1'+i)) + "0"
			hms := "19:" + twoDigits(minute) + ":" + sec
			b.WriteString(line(peer, hms, "GET /shop/?s=ring HTTP/1.1", "200", "") + "\n")
			if minute == 20 && sec == "40" {
				b.WriteString(line("192.0.2.90", "19:20:41", "GET /x HTTP/1.1", "200", ` "`+strings.Repeat("A", 70000)+`"`) + "\n")
			}
		}
		switch minute {
		case 8:
			b.WriteString(line("192.0.2.99", "19:08:50", "GET /"+strings.Repeat("a", 9000)+" HTTP/1.1", "414", "") + "\n")
		case 14:
			b.WriteString(line("198.51.100.9", "19:14:50", "GET /shop/?s=ring HTTP/1.1", "200", "") + "\n")
		}
	}
	c := convertLogs(t, []synthLog{{name: "example.com", data: b.String()}}, "")
	p0 := c.manifest.Period.From
	span := func(from, to int64) crawlreplay.Span { return crawlreplay.Span{From: p0 + from, To: p0 + to} }
	params := crawlreplay.Params{W: 3, R: 3, F: 1, K: 1, D: 2, C: 80,
		Baseline: crawlreplay.BaselineParams{Alpha: 0.1, MinObs: 1, MinAge: 7 * 24 * 60, FloorPerMin: 1}}
	replay := func(site crawlreplay.BundleSite) map[int64]int {
		ticks := map[int64]int{}
		in := crawlreplay.Site{Records: crawlreplay.RestrictToCoverage(c.records, site.Coverage), Coverage: site.Coverage}
		if err := crawlreplay.ReplaySite(in, params, crawlreplay.Options{}, func(tk crawlreplay.Tick) {
			ticks[tk.Minute] = len(tk.Evaluations)
		}); err != nil {
			t.Fatal(err)
		}
		return ticks
	}
	minutes := func(ticks map[int64]int) []int64 {
		out := slices.Collect(func(yield func(int64) bool) {
			for m := range ticks {
				if !yield(m - p0) {
					return
				}
			}
		})
		slices.Sort(out)
		return out
	}
	rangeOf := func(from, to int64) []int64 {
		var out []int64
		for m := from; m <= to; m++ {
			out = append(out, m)
		}
		return out
	}

	// The malformed first line may belong anywhere before 19:01:05 plus the
	// lateness bound; the 414 line has no target however it was answered;
	// the proxied line has no client; the oversized line lies between
	// 19:20:40 and 19:21:05, widened by a minute on each side.
	site := validateConverted(t, c, coverageProof(t, c, nil))
	want := []crawlreplay.Span{span(3, 7), span(9, 13), span(15, 18), span(23, 29)}
	if !reflect.DeepEqual(site.Coverage, want) {
		t.Fatalf("coverage = %+v, want %+v", site.Coverage, want)
	}
	got := minutes(replay(site))
	wantTicks := slices.Concat(rangeOf(5, 7), rangeOf(11, 13), rangeOf(17, 18), rangeOf(25, 29))
	if !slices.Equal(got, wantTicks) {
		t.Fatalf("evaluated minutes = %v, want %v", got, wantTicks)
	}

	// Independent evidence that the 414 and the oversized request never
	// reached the application keeps the crawl's windows complete.
	waived := validateConverted(t, c, coverageProof(t, c, []crawlreplay.RejectWaiver{
		{From: p0 + 8, To: p0 + 8, Category: crawlreplay.LossNoTarget, Lines: 1, Evidence: strings.Repeat("f", 64)},
		{From: p0 + 19, To: p0 + 22, Category: crawlreplay.LossOversized, Lines: 1, Evidence: strings.Repeat("f", 64)},
	}))
	if want := []crawlreplay.Span{span(3, 13), span(15, 29)}; !reflect.DeepEqual(waived.Coverage, want) {
		t.Fatalf("waived coverage = %+v, want %+v", waived.Coverage, want)
	}
	ticks := replay(waived)
	if !slices.Equal(minutes(ticks), slices.Concat(rangeOf(5, 13), rangeOf(17, 29))) || ticks[p0+22] == 0 {
		t.Fatalf("waived replay minutes = %v, crawl window at minute 22 evaluated %d keys", minutes(ticks), ticks[p0+22])
	}
}

func twoDigits(n int) string {
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
