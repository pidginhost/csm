package checks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/jstaint"
)

// jsKeyloggerFixture is the shared two_scalar_hops regex-gap shape: a
// keystroke laundered through two variables into a fetch URL. The corpus
// gate and both regex-gap suites pin that the engine detects it.
const jsKeyloggerFixture = `document.addEventListener("keydown",function(e){var c=e.which;var ch=String.fromCharCode(c);var out="";out+=ch;fetch("/c?k="+out);});`

// jsCleanCandidateFixture passes the content pre-filter (keydown + fetch
// tokens) but has no keystroke-to-sink flow, so analysis completes negative.
const jsCleanCandidateFixture = `document.addEventListener("keydown",function(e){console.log(e.type);});fetch("/health");`

func writeVerifyJSFixture(t *testing.T, root, name, content string) (path, hash string) {
	t.Helper()
	path = filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return path, fmt.Sprintf("%x", sum)
}

func verifyJSFinding(path, hash string) VerifyResult {
	return VerifyFindingInput(VerifyInput{
		Check:         "js_keylogger_dataflow",
		Message:       "JavaScript keystroke exfiltration data flow: " + path,
		Path:          path,
		ContentSHA256: hash,
	})
}

func TestVerifyJSKeyloggerStillFlaggedStaysOpen(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)
	path, hash := writeVerifyJSFixture(t, root, "probe.js", jsKeyloggerFixture)

	res := verifyJSFinding(path, hash)
	if !res.Checked || res.Resolved {
		t.Fatalf("still-infected file = %+v, want checked and unresolved", res)
	}
	if !strings.Contains(res.Detail, "still flagged") {
		t.Fatalf("detail = %q, want current-detection confirmation", res.Detail)
	}
}

func TestVerifyJSKeyloggerMissingFileResolves(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)

	res := verifyJSFinding(filepath.Join(root, "gone.js"), strings.Repeat("a", 64))
	if !res.Checked || !res.Resolved {
		t.Fatalf("missing file = %+v, want checked and resolved", res)
	}
}

func TestVerifyJSKeyloggerSupersededNegativeResolves(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)
	path, hash := writeVerifyJSFixture(t, root, "clean.js", jsCleanCandidateFixture)

	res := verifyJSFinding(path, hash)
	if !res.Checked || !res.Resolved {
		t.Fatalf("identical completed-negative bytes = %+v, want resolved as superseded detection", res)
	}
}

func TestVerifyJSKeyloggerNotCandidateWithEqualHashResolves(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)
	path, hash := writeVerifyJSFixture(t, root, "plain.js", `console.log("hello");`)

	res := verifyJSFinding(path, hash)
	if !res.Checked || !res.Resolved {
		t.Fatalf("not-candidate bytes with equal hash = %+v, want resolved", res)
	}
}

func TestVerifyJSKeyloggerModifiedCleanFileStaysOpen(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)
	path, _ := writeVerifyJSFixture(t, root, "edited.js", jsCleanCandidateFixture)

	res := verifyJSFinding(path, strings.Repeat("0", 64))
	if !res.Checked || res.Resolved {
		t.Fatalf("hash-mismatched clean file = %+v, want checked but never auto-cleared", res)
	}
}

func TestVerifyJSKeyloggerParseErrorNotChecked(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)
	path, hash := writeVerifyJSFixture(t, root, "broken.js", "keydown fetch ((((")

	res := verifyJSFinding(path, hash)
	if res.Checked || res.Resolved {
		t.Fatalf("parse-error file = %+v, want not checked (fail closed)", res)
	}
}

func TestVerifyJSKeyloggerOversizeNotChecked(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)
	path, hash := writeVerifyJSFixture(t, root, "big.js", strings.Repeat("+", jstaint.MaxSourceBytes+1))

	res := verifyJSFinding(path, hash)
	if res.Checked || res.Resolved {
		t.Fatalf("oversize file = %+v, want not checked (fail closed)", res)
	}
}

func TestVerifyJSKeyloggerCoverageGapStatusesNotChecked(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)
	path, hash := writeVerifyJSFixture(t, root, "probe.js", jsKeyloggerFixture)

	for _, status := range []jstaint.Status{
		jstaint.StatusResourceLimit,
		jstaint.StatusCanceled,
		jstaint.StatusPanic,
	} {
		t.Run(status.String(), func(t *testing.T) {
			prev := jsTaintAnalyze
			jsTaintAnalyze = func(context.Context, []byte) jstaint.Report {
				return jstaint.Report{Status: status, Reason: status.String()}
			}
			t.Cleanup(func() { jsTaintAnalyze = prev })

			res := verifyJSFinding(path, hash)
			if res.Checked || res.Resolved {
				t.Fatalf("status %s = %+v, want not checked (fail closed)", status, res)
			}
		})
	}
}

func TestVerifyJSKeyloggerAdapterPanicNotChecked(t *testing.T) {
	root, _ := redirectQuarantineForFullScan(t)
	path, hash := writeVerifyJSFixture(t, root, "probe.js", jsKeyloggerFixture)

	prev := jsTaintAnalyze
	jsTaintAnalyze = func(context.Context, []byte) jstaint.Report {
		panic("forced adapter panic")
	}
	t.Cleanup(func() { jsTaintAnalyze = prev })

	res := verifyJSFinding(path, hash)
	if res.Checked || res.Resolved {
		t.Fatalf("adapter panic = %+v, want not checked (fail closed)", res)
	}
}
