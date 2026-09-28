package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/pidginhost/csm/internal/crawlreplay"
)

var updateGolden = flag.Bool("update", false, "rewrite the round-trip golden report")

// roundTrip is the bundle scripts/domlog-stream's round-trip test requires
// its real entry point to produce, byte for byte. The experiment names it
// relative to its own directory.
const roundTrip = "../domlog-stream/testdata/roundtrip"

func roundTripArgs(out string) []string {
	return []string{"--experiment", "testdata/roundtrip-experiment.json", "--out", out}
}

// TestConverterCalibratorRoundTrip replays the converter's golden bundle
// with a proof bound to its manifest and requires the golden report.
func TestConverterCalibratorRoundTrip(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.json")
	if err := run(roundTripArgs(out), testEnv()); err != nil {
		t.Fatal(err)
	}
	got := mustRead(t, out)
	golden := "testdata/roundtrip-report.json"
	if *updateGolden {
		if err := os.WriteFile(golden, got, 0o600); err != nil {
			t.Fatal(err)
		}
	} else if !bytes.Equal(got, mustRead(t, golden)) {
		t.Fatal("report differs from the golden report; rerun with -update only for an intended change")
	}
	for _, raw := range []string{"example.com", "shop.example", "acct1", "192.0.2", "198.51.100", "203.0.113", "filter_", "testdata"} {
		if bytes.Contains(got, []byte(raw)) {
			t.Fatalf("report leaks %q", raw)
		}
	}
	rep := readReport(t, out)
	sum := sha256.Sum256(mustRead(t, roundTrip+"/manifest.json"))
	proof := sha256.Sum256(mustRead(t, "testdata/roundtrip-coverage.json"))
	experimentSum := sha256.Sum256(mustRead(t, "testdata/roundtrip-experiment.json"))
	p := rep.Provenance
	if p.ExperimentSHA256 != hex.EncodeToString(experimentSum[:]) || p.Coverage != coverageCertified || p.Calibrator != calibratorTool() ||
		len(p.Bundles) != 1 {
		t.Fatalf("provenance = %+v", p)
	}
	if bp := p.Bundles[0]; bp.ManifestSHA256 != hex.EncodeToString(sum[:]) || bp.ProofSHA256 != hex.EncodeToString(proof[:]) ||
		bp.Coverage != coverageCertified || !bp.Converter.Clean() || bp.LatenessSeconds != 60 || bp.BotEvidence == nil || bp.Role != roleScoring {
		t.Fatalf("bundle provenance = %+v", bp)
	}
	// The malformed line lies between 19:05:10 and 19:05:40 give or take the
	// lateness bound, and the targetless line is at 19:07:30: minutes 4 to 7
	// of example.com are not covered. The shop site's proof excludes its
	// last two minutes.
	a, s := rep.Coverage[0], rep.Coverage[1]
	if a.CertifiedMinutes != 20 || a.CoveredMinutes != 16 || a.Excluded[crawlreplay.ExcludedUnknownLoss] != 4 ||
		a.Lines["records"] != 75 || a.Lines["rejected"] != 1 || a.Lines["no_target"] != 1 {
		t.Fatalf("example.com coverage = %+v", a)
	}
	if s.CertifiedMinutes != 18 || s.CoveredMinutes != 18 || s.Excluded[crawlreplay.ExcludedLivenessUnknown] != 2 {
		t.Fatalf("shop coverage = %+v", s)
	}
	if len(rep.Runs) != 2 || len(rep.Runs[0].Scoring.Episodes) != 1 || !rep.Runs[0].Scoring.Episodes[0].Detected ||
		rep.Runs[0].Scoring.Episodes[0].Site != "dom-a01dff.example" {
		t.Fatalf("runs = %+v", rep.Runs)
	}
	for _, e := range rep.Runs[0].Scoring.Events {
		if len(e.Credited) == 0 {
			t.Fatalf("uncredited transition %+v in the round trip", e)
		}
	}
}

func TestCalibrateRequiresCoverageForGrid(t *testing.T) {
	b := writeBundle(t, bundleOptions{})
	noProof := b.experiment()
	noProof.Bundles[0].Coverage = ""
	if err := run(b.with(t, noProof), testEnv()); !errors.Is(err, errCoverage) {
		t.Fatalf("grid without a proof: %v", err)
	}
	other := writeBundle(t, bundleOptions{pad: 1})
	if err := os.Rename(other.coverage, b.coverage); err != nil {
		t.Fatal(err)
	}
	if err := run(b.args(t), testEnv()); !errors.Is(err, errCoverage) {
		t.Fatalf("proof bound to another manifest: %v", err)
	}
	if err := os.WriteFile(b.coverage, []byte(`{"format_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(b.args(t), testEnv()); !errors.Is(err, errCoverage) {
		t.Fatalf("malformed proof: %v", err)
	}
	if _, err := os.Stat(b.out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused run wrote a report")
	}
}

func TestCalibrateValidatesWithoutGrid(t *testing.T) {
	b := writeBundle(t, bundleOptions{})
	diagnostics := b.experiment()
	diagnostics.Runs, diagnostics.Bundles[0].Coverage = []gridRun{}, ""
	if err := run(b.with(t, diagnostics), testEnv()); err != nil {
		t.Fatal(err)
	}
	rep := readReport(t, b.out)
	if rep.Provenance.Coverage != coverageUnqualified || rep.Provenance.Bundles[0].ProofSHA256 != "" || len(rep.Runs) != 0 ||
		rep.Coverage[0].CertifiedMinutes != 0 || rep.Coverage[0].Extent == nil || len(rep.Silences) != 2 {
		t.Fatalf("unqualified report = %+v", rep)
	}
	bad := writeBundle(t, bundleOptions{})
	m, err := crawlreplay.DecodeManifest(mustRead(t, bad.manifest))
	if err != nil {
		t.Fatal(err)
	}
	m.Sites[1].Records++
	m.Sites[1].Lines++
	m.Sites[1].Labels[crawlreplay.LabelHealthy]++
	raw, err := crawlreplay.EncodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(bad.manifest, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	unqualified := bad.experiment()
	unqualified.Runs, unqualified.Bundles[0].Coverage = []gridRun{}, ""
	if err = run(bad.with(t, unqualified), testEnv()); !errors.Is(err, errBundle) {
		t.Fatalf("manifest totals that disagree with the rows: %v", err)
	}
	if _, err = os.Stat(bad.out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused bundle wrote a report")
	}
}

func TestCalibrateInputsMustBeRegularFiles(t *testing.T) {
	b := writeBundle(t, bundleOptions{})
	link := filepath.Join(b.dir, "records-link.jsonl.gz")
	if err := os.Symlink(b.records, link); err != nil {
		t.Fatal(err)
	}
	x := b.experiment()
	x.Bundles[0].Records = link
	if err := run(b.with(t, x), testEnv()); !errors.Is(err, errBundle) {
		t.Fatalf("symlinked records: %v", err)
	}
	fifo := filepath.Join(b.dir, "manifest.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	x = b.experiment()
	x.Bundles[0].Manifest = fifo
	if err := run(b.with(t, x), testEnv()); !errors.Is(err, errManifest) {
		t.Fatalf("FIFO manifest: %v", err)
	}
	// The experiment file itself is held to the same rule.
	args := b.args(t)
	experimentLink := filepath.Join(b.dir, "experiment-link.json")
	if err := os.Symlink(args[1], experimentLink); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--experiment", experimentLink, "--out", b.out}, testEnv()); !errors.Is(err, errExperiment) {
		t.Fatalf("symlinked experiment: %v", err)
	}
	experimentFIFO := filepath.Join(b.dir, "experiment.fifo")
	if err := syscall.Mkfifo(experimentFIFO, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--experiment", experimentFIFO, "--out", b.out}, testEnv()); !errors.Is(err, errExperiment) {
		t.Fatalf("FIFO experiment: %v", err)
	}
}

func TestCalibrateCLIReportsFixedErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"unknown flag":  {"--secret-value", "/private/secret-file"},
		"stray operand": {"--experiment", "/private/secret-file", "--out", "/private/secret-out", "secret-target"},
	} {
		var stderr bytes.Buffer
		if code := cli(args, &stderr, testEnv()); code != 1 || stderr.String() != "crawl-calibrate: "+string(errUsage)+"\n" {
			t.Errorf("%s: exit %d stderr %q", name, code, stderr.String())
		}
	}
	b := writeBundle(t, bundleOptions{})
	var stderr bytes.Buffer
	if code := cli(b.args(t), &stderr, defaultEnv()); code != 1 || stderr.String() != "crawl-calibrate: "+string(errDirtyBuild)+"\n" {
		t.Fatalf("unstamped build: exit %d stderr %q", code, stderr.String())
	}
	if strings.Contains(stderr.String(), b.dir) {
		t.Fatal("stderr names a path")
	}
}
