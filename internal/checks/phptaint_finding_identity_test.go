package checks

import (
	"encoding/json"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/phptaint"
)

func identityReport(results ...phptaint.Result) phptaint.Report {
	return phptaint.Report{Status: phptaint.StatusAnalyzed, TotalResults: len(results), Results: results}
}

func identityResult(source, sink string, c phptaint.Confidence, b phptaint.Basis) phptaint.Result {
	return phptaint.Result{Source: source, Sink: sink, Confidence: c, Basis: b, ResolutionOffset: -1}
}

// A php_remote_taint finding's identity is the file, the severity and the
// set of endpoint pairs. Details wording, basis and evidence context change
// between releases; if they fed the key, every stored finding would re-key,
// lose its dismissal and re-alert on each such change.
func TestPHPTaintFindingIdentityIgnoresWording(t *testing.T) {
	base := phpTaintDeepFinding("/home/u/public_html/x.php", "sha-a", identityReport(
		identityResult("curl_exec", "eval", phptaint.ConfidenceHigh, phptaint.BasisAlwaysRemote),
		identityResult("file_get_contents", "include", phptaint.ConfidenceLow, phptaint.BasisUnresolved),
	))
	if base.DedupKey == "" {
		t.Fatal("php_remote_taint finding has no pinned identity")
	}

	reworded := base
	reworded.Details = "different wording of the same evidence"
	reworded.Message = "different message"

	otherBasis := identityReport(
		// Same endpoints and severity, different basis, order and context.
		identityResult("file_get_contents", "include", phptaint.ConfidenceLow, phptaint.BasisCallArgument),
		identityResult("curl_exec", "eval", phptaint.ConfidenceHigh, phptaint.BasisLiteral),
		identityResult("curl_exec", "eval", phptaint.ConfidenceLow, phptaint.BasisUnresolved),
	)
	otherBasis.Results[0].Identifiers = []string{"$u"}
	otherBasis.TotalResults = 9
	otherBasis.EvidenceTruncated = true
	otherBasis.PrecisionLoss = []string{"extract"}

	for name, f := range map[string]alert.Finding{
		"reworded details":             reworded,
		"basis, order, context, bytes": phpTaintDeepFinding("/home/u/public_html/x.php", "sha-b", otherBasis),
	} {
		if f.Key() != base.Key() || f.Fingerprint() != base.Fingerprint() {
			t.Errorf("%s: key %q / %q, want %q / %q", name, f.Key(), f.Fingerprint(), base.Key(), base.Fingerprint())
		}
	}
}

func TestPHPTaintFindingIdentityFollowsPathSeverityAndEndpoints(t *testing.T) {
	flow := identityResult("curl_exec", "eval", phptaint.ConfidenceHigh, phptaint.BasisAlwaysRemote)
	base := phpTaintDeepFinding("/home/u/x.php", "sha", identityReport(flow))

	certain := flow
	certain.Confidence = phptaint.ConfidenceCertain
	otherSink := flow
	otherSink.Sink = "include"
	otherSource := flow
	otherSource.Source = "fsockopen"

	for name, f := range map[string]alert.Finding{
		"path":         phpTaintDeepFinding("/home/u/y.php", "sha", identityReport(flow)),
		"severity":     phpTaintDeepFinding("/home/u/x.php", "sha", identityReport(certain)),
		"added pair":   phpTaintDeepFinding("/home/u/x.php", "sha", identityReport(flow, otherSink)),
		"other sink":   phpTaintDeepFinding("/home/u/x.php", "sha", identityReport(otherSink)),
		"other source": phpTaintDeepFinding("/home/u/x.php", "sha", identityReport(otherSource)),
	} {
		if f.Key() == base.Key() {
			t.Errorf("%s change kept key %q", name, f.Key())
		}
	}
}

// Endpoint fields are length-delimited, so moving text between the source
// and the sink of a pair cannot produce the same identity.
func TestPHPTaintFindingIdentityDelimitsEndpoints(t *testing.T) {
	a := phpTaintDeepFinding("/x.php", "sha", identityReport(identityResult("$o->b", "eval", phptaint.ConfidenceHigh, phptaint.BasisLiteral)))
	b := phpTaintDeepFinding("/x.php", "sha", identityReport(identityResult("$o", "b->eval", phptaint.ConfidenceHigh, phptaint.BasisLiteral)))
	if a.Key() == b.Key() {
		t.Fatalf("different endpoint pairs share key %q", a.Key())
	}
}

// A finding carried forward over a coverage gap is the stored copy, so it
// must keep the identity the fresh finding was stored under, through the
// persisted JSON form.
func TestPHPTaintCarriedFindingKeepsItsKey(t *testing.T) {
	const path = "/home/u/public_html/x.php"
	fresh := phpTaintDeepFinding(path, "sha", identityReport(
		identityResult("curl_exec", "eval", phptaint.ConfidenceHigh, phptaint.BasisAlwaysRemote)))

	raw, err := json.Marshal(fresh)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var stored alert.Finding
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	gaps := newPHPTaintGapCollector()
	gaps.record(path, phptaint.StatusTimeout.String())
	carried := carryForwardPHPTaintFindings([]alert.Finding{stored}, gaps)
	if len(carried) != 1 {
		t.Fatalf("carried = %+v, want the stored finding", carried)
	}
	if carried[0].Key() != fresh.Key() || carried[0].Fingerprint() != fresh.Fingerprint() {
		t.Fatalf("carried key %q, want %q", carried[0].Key(), fresh.Key())
	}
}
