package phptaintipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/phptaint"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := Frame{Op: OpAnalyze, Payload: []byte(`{"source":"PD9waHA="}`)}
	if err := WriteFrame(&buf, want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Op != want.Op || string(got.Payload) != string(want.Payload) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

type chunkWriter struct {
	bytes.Buffer
	max int
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.Buffer.Write(p)
}

func TestWriteFrameCompletesShortWrites(t *testing.T) {
	var wire chunkWriter
	wire.max = 2
	want := Frame{Op: OpPing}
	if err := WriteFrame(&wire, want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadFrame(&wire.Buffer)
	if err != nil {
		t.Fatalf("read frame written in short chunks: %v", err)
	}
	if got.Op != want.Op {
		t.Fatalf("op = %q, want %q", got.Op, want.Op)
	}
}

// TestReadFrameRejectsOversizeHeaderWithoutAllocating is the one that matters
// for a hostile peer: the length prefix is attacker-influenced, so a frame
// claiming 4 GiB must be refused from the header alone. Allocating first and
// discovering the truth afterwards is how a peer turns a 4-byte write into an
// out-of-memory kill.
func TestReadFrameRejectsOversizeHeaderWithoutAllocating(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], ^uint32(0))
	_, err := ReadFrame(bytes.NewReader(hdr[:]))
	if err == nil {
		t.Fatal("oversize length prefix accepted, want error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want it to name the cap", err)
	}
}

func TestWriteFrameRejectsOversizeBody(t *testing.T) {
	big := Frame{Op: OpAnalyze, Payload: make([]byte, MaxFrameBytes+1)}
	for i := range big.Payload {
		big.Payload[i] = 'a'
	}
	if err := WriteFrame(io.Discard, big); err == nil {
		t.Fatal("oversize body accepted, want error")
	}
}

func TestReadFrameOnTruncatedBody(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Frame{Op: OpPing}); err != nil {
		t.Fatalf("write: %v", err)
	}
	truncated := buf.Bytes()[:buf.Len()-1]
	if _, err := ReadFrame(bytes.NewReader(truncated)); err == nil {
		t.Fatal("truncated frame accepted, want error")
	}
}

func TestEncodeDecodeAnalyzeArgs(t *testing.T) {
	src := []byte("<?php eval(curl_exec($c));")
	frame, err := EncodePayload(OpAnalyze, AnalyzeArgs{Source: src})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got AnalyzeArgs
	if err := DecodePayload(frame, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got.Source, src) {
		t.Fatalf("source = %q, want %q", got.Source, src)
	}
}

func TestEncodePayloadNilOmitsPayload(t *testing.T) {
	frame, err := EncodePayload(OpPing, nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if frame.Op != OpPing || len(frame.Payload) != 0 {
		t.Fatalf("frame = %+v, want ping without a payload", frame)
	}
}

// TestAnalyzeArgsRejectsOversizeSource keeps the size decision in one place.
// phptaint already refuses to analyze a source above its own ceiling and
// reports that as a coverage gap; the wire must refuse the same input rather
// than spend a multi-megabyte frame discovering it.
func TestAnalyzeArgsRejectsOversizeSource(t *testing.T) {
	_, err := EncodePayload(OpAnalyze, AnalyzeArgs{Source: make([]byte, phptaint.MaxSourceBytes+1)})
	if !errors.Is(err, ErrSourceTooLarge) {
		t.Fatalf("error = %v, want ErrSourceTooLarge", err)
	}
}

func TestAnalyzeArgsAtSourceLimitFitsFrame(t *testing.T) {
	frame, err := EncodePayload(OpAnalyze, AnalyzeArgs{Source: make([]byte, phptaint.MaxSourceBytes)})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := WriteFrame(io.Discard, frame); err != nil {
		t.Fatalf("write exact-limit source: %v", err)
	}
}

func TestAnalyzeArgsPointerRejectsOversizeSource(t *testing.T) {
	_, err := EncodePayload(OpAnalyze, &AnalyzeArgs{Source: make([]byte, phptaint.MaxSourceBytes+1)})
	if !errors.Is(err, ErrSourceTooLarge) {
		t.Fatalf("error = %v, want ErrSourceTooLarge", err)
	}
}

func TestDecodeAnalyzeArgsRejectsOversizeSource(t *testing.T) {
	raw, err := json.Marshal(AnalyzeArgs{Source: make([]byte, phptaint.MaxSourceBytes+1)})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	var got AnalyzeArgs
	if err := DecodePayload(Frame{Payload: raw}, &got); !errors.Is(err, ErrSourceTooLarge) {
		t.Fatalf("error = %v, want ErrSourceTooLarge", err)
	}
}

func TestDecodeAnalyzeArgsRejectsMissingSource(t *testing.T) {
	got := AnalyzeArgs{Source: []byte("previous request")}
	if err := DecodePayload(Frame{Payload: []byte(`{}`)}, &got); err == nil {
		t.Fatal("payload without source accepted, want error")
	}
	if string(got.Source) != "previous request" {
		t.Fatalf("failed decode changed target to %q", got.Source)
	}
}

// TestAnalyzeResultCarriesReportVerbatim guards the reason this package shares
// phptaint's own Report type instead of restating it: worker and daemon are the
// same binary, so a translation layer could only add drift, and a status this
// package failed to map would be read as a zero value -- StatusNotCandidate,
// which means "clean". A coverage gap must never decay into a clean result.
func TestAnalyzeResultCarriesReportVerbatim(t *testing.T) {
	want := phptaint.Report{
		Status:            phptaint.StatusAnalyzed,
		PrecisionLoss:     []string{"closure-capture"},
		TotalResults:      1,
		EvidenceTruncated: true,
		Results: []phptaint.Result{
			{Source: "curl_exec", Sink: "eval", Confidence: phptaint.ConfidenceCertain, Identifiers: []string{"$p"},
				Basis: phptaint.BasisLiteral, ResolutionOffset: -1},
		},
	}
	frame, err := EncodePayload("", AnalyzeResult{Report: want})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got AnalyzeResult
	if err := DecodePayload(frame, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Report.Status != want.Status || got.Report.TotalResults != want.TotalResults ||
		got.Report.Reason != "" || !got.Report.EvidenceTruncated ||
		len(got.Report.Results) != 1 || got.Report.Results[0].Sink != "eval" ||
		got.Report.Results[0].Confidence != phptaint.ConfidenceCertain ||
		got.Report.Results[0].Basis != phptaint.BasisLiteral ||
		len(got.Report.PrecisionLoss) != 1 {
		t.Fatalf("report round trip lost data: %+v", got.Report)
	}
}

func TestAnalyzeResultCarriesCoverageGapVerbatim(t *testing.T) {
	want := phptaint.Report{Status: phptaint.StatusPartialParse, Reason: "partial_parse: recovered syntax error"}
	frame, err := EncodePayload("", AnalyzeResult{Report: want})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got AnalyzeResult
	if err := DecodePayload(frame, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Report.Status != want.Status || got.Report.Reason != want.Reason {
		t.Fatalf("report round trip = %+v, want %+v", got.Report, want)
	}
}

func TestAnalyzeResultCarriesExplicitNotCandidateStatus(t *testing.T) {
	frame, err := EncodePayload("", AnalyzeResult{Report: phptaint.Report{Status: phptaint.StatusNotCandidate}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got AnalyzeResult
	if err := DecodePayload(frame, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Report.Status != phptaint.StatusNotCandidate {
		t.Fatalf("status = %v, want StatusNotCandidate", got.Report.Status)
	}
}

func TestAnalyzeResultRejectsMissingStatus(t *testing.T) {
	got := AnalyzeResult{Report: phptaint.Report{Status: phptaint.StatusAnalyzed}}
	if err := DecodePayload(Frame{Payload: []byte(`{"report":{}}`)}, &got); err == nil {
		t.Fatal("report without status accepted, want error")
	}
	if got.Report.Status != phptaint.StatusAnalyzed {
		t.Fatalf("failed decode changed status to %v", got.Report.Status)
	}
}

func TestAnalyzeResultRejectsUnknownStatus(t *testing.T) {
	var got AnalyzeResult
	err := DecodePayload(Frame{Payload: []byte(`{"report":{"Status":255}}`)}, &got)
	if err == nil {
		t.Fatal("unknown report status accepted, want error")
	}
}

func TestAnalyzeResultRejectsEvidenceOnCoverageGap(t *testing.T) {
	_, err := EncodePayload("", AnalyzeResult{Report: phptaint.Report{
		Status:       phptaint.StatusPartialParse,
		Reason:       "partial_parse",
		Results:      []phptaint.Result{{Source: "curl_exec", Sink: "eval"}},
		TotalResults: 1,
	}})
	if err == nil {
		t.Fatal("coverage-gap report with evidence accepted, want error")
	}
}

func TestAnalyzeResultRejectsMissingEvidence(t *testing.T) {
	_, err := EncodePayload("", AnalyzeResult{Report: phptaint.Report{
		Status:       phptaint.StatusAnalyzed,
		TotalResults: 1,
	}})
	if err == nil {
		t.Fatal("analyzed report that omitted a finding was accepted")
	}
}

func TestAnalyzeResultCarriesBoundedEvidence(t *testing.T) {
	results := make([]phptaint.Result, phptaint.MaxEvidenceResults)
	for i := range results {
		results[i] = phptaint.Result{Basis: phptaint.BasisAlwaysRemote, ResolutionOffset: -1}
	}
	frame, err := EncodePayload("", AnalyzeResult{Report: phptaint.Report{
		Status:            phptaint.StatusAnalyzed,
		Results:           results,
		TotalResults:      phptaint.MaxEvidenceResults + 1,
		EvidenceTruncated: true,
	}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got AnalyzeResult
	if err := DecodePayload(frame, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestAnalyzeResultRejectsUnmarkedEvidenceTruncation(t *testing.T) {
	results := make([]phptaint.Result, phptaint.MaxEvidenceResults)
	for i := range results {
		results[i] = phptaint.Result{Basis: phptaint.BasisAlwaysRemote, ResolutionOffset: -1}
	}
	_, err := EncodePayload("", AnalyzeResult{Report: phptaint.Report{
		Status:       phptaint.StatusAnalyzed,
		Results:      results,
		TotalResults: phptaint.MaxEvidenceResults + 1,
	}})
	if err == nil {
		t.Fatal("analyzed report with unmarked evidence truncation was accepted")
	}
}

func TestAnalyzeResultRejectsUnknownConfidence(t *testing.T) {
	_, err := EncodePayload("", AnalyzeResult{Report: phptaint.Report{
		Status: phptaint.StatusAnalyzed,
		Results: []phptaint.Result{{
			Source:           "curl_exec",
			Sink:             "eval",
			Confidence:       phptaint.Confidence(255),
			Basis:            phptaint.BasisAlwaysRemote,
			ResolutionOffset: -1,
		}},
		TotalResults: 1,
	}})
	if err == nil {
		t.Fatal("analyzed report with unknown confidence was accepted")
	}
}

func TestAnalyzeResultRejectsSupervisorOnlyStatuses(t *testing.T) {
	for _, status := range []phptaint.Status{phptaint.StatusTimeout, phptaint.StatusWorkerFailure} {
		_, err := EncodePayload("", AnalyzeResult{Report: phptaint.Report{
			Status: status,
			Reason: status.String(),
		}})
		if err == nil {
			t.Errorf("worker reply with status %v was accepted", status)
		}
	}
}

func validResult() phptaint.Result {
	return phptaint.Result{Source: "curl_exec", Sink: "eval", Confidence: phptaint.ConfidenceHigh,
		Basis: phptaint.BasisAlwaysRemote, ResolutionOffset: -1}
}

func analyzedWith(r phptaint.Result) phptaint.Report {
	return phptaint.Report{Status: phptaint.StatusAnalyzed, TotalResults: 1, Results: []phptaint.Result{r}}
}

func TestAnalyzeResultRejectsMissingOrUnknownBasis(t *testing.T) {
	for _, basis := range []phptaint.Basis{"", "remote"} {
		r := validResult()
		r.Basis = basis
		if _, err := EncodePayload("", AnalyzeResult{Report: analyzedWith(r)}); err == nil {
			t.Errorf("basis %q accepted", basis)
		}
	}
}

// A reply from a worker built before Basis existed has no basis field. It
// must fail as a worker error, never decode into an empty-basis success.
func TestDecodeRejectsPreBasisReply(t *testing.T) {
	// The real encoding of a valid one-result report with only the Basis and
	// ResolutionOffset keys removed. The control below restores them and must
	// decode, so the missing basis is the literal's only defect.
	const preBasis = `{"report":{"Status":1,"Results":[{"Source":"curl_exec","Identifiers":null,"Sink":"eval","Confidence":1}],"TotalResults":1,"Reason":"","PrecisionLoss":null,"EvidenceTruncated":false}}`
	const restored = `{"report":{"Status":1,"Results":[{"Source":"curl_exec","Identifiers":null,"Sink":"eval","Confidence":1,"Basis":"always-remote","ResolutionOffset":-1}],"TotalResults":1,"Reason":"","PrecisionLoss":null,"EvidenceTruncated":false}}`
	var control AnalyzeResult
	if err := DecodePayload(Frame{Payload: []byte(restored)}, &control); err != nil {
		t.Fatalf("control with basis restored rejected: %v", err)
	}
	var got AnalyzeResult
	if err := DecodePayload(Frame{Payload: []byte(preBasis)}, &got); err == nil {
		t.Fatalf("pre-basis reply decoded: %+v", got.Report)
	}
}

func TestAnalyzeResultRejectsOffsetBelowMinusOne(t *testing.T) {
	r := validResult()
	r.ResolutionOffset = -2
	if _, err := EncodePayload("", AnalyzeResult{Report: analyzedWith(r)}); err == nil {
		t.Fatal("offset -2 accepted")
	}
}

func TestValidateReportForSourceBoundsOffset(t *testing.T) {
	r := validResult()
	r.Basis = phptaint.BasisCallArgument
	for _, tc := range []struct {
		offset, n int
		ok        bool
	}{
		{-1, 10, true}, {0, 10, true}, {9, 10, true}, {10, 10, false}, {0, 0, false},
	} {
		r.ResolutionOffset = tc.offset
		err := ValidateReportForSource(analyzedWith(r), tc.n)
		if (err == nil) != tc.ok {
			t.Errorf("offset %d in %d bytes: err = %v, want ok=%v", tc.offset, tc.n, err, tc.ok)
		}
	}
}

// resultReply is the real encoding of a valid one-result report (see
// TestDecodeRejectsPreBasisReply) with the result's Basis and ResolutionOffset
// keys replaced by keys. TestDecodeResultReplyControl proves the complete form
// decodes, so each rejection turns on the keys alone.
func resultReply(keys string) []byte {
	return []byte(`{"report":{"Status":1,"Results":[{"Source":"curl_exec","Identifiers":null,"Sink":"eval","Confidence":1` +
		keys + `}],"TotalResults":1,"Reason":"","PrecisionLoss":null,"EvidenceTruncated":false}}`)
}

func TestDecodeResultReplyControl(t *testing.T) {
	var got AnalyzeResult
	if err := DecodePayload(Frame{Payload: resultReply(`,"Basis":"call-argument","ResolutionOffset":5`)}, &got); err != nil {
		t.Fatalf("complete reply rejected: %v", err)
	}
	if got.Report.Results[0].ResolutionOffset != 5 || got.Report.Results[0].Basis != phptaint.BasisCallArgument {
		t.Fatalf("complete reply decoded as %+v", got.Report.Results[0])
	}
}

// A missing offset decodes to 0, a real position. It must be a worker error,
// never evidence resolved at the first byte.
func TestDecodeRejectsResultWithoutOffset(t *testing.T) {
	var got AnalyzeResult
	if err := DecodePayload(Frame{Payload: resultReply(`,"Basis":"call-argument"`)}, &got); err == nil {
		t.Fatalf("reply without offset decoded: %+v", got.Report)
	}
}

// twoResultReply is a valid two-result report whose second result's Basis
// and ResolutionOffset keys are replaced by second.
func twoResultReply(second string) []byte {
	return []byte(`{"report":{"Status":1,"Results":[` +
		`{"Source":"curl_exec","Identifiers":null,"Sink":"eval","Confidence":1,"Basis":"always-remote","ResolutionOffset":-1},` +
		`{"Source":"fsockopen","Identifiers":null,"Sink":"include","Confidence":1` + second + `}` +
		`],"TotalResults":2,"Reason":"","PrecisionLoss":null,"EvidenceTruncated":false}}`)
}

// Every result is checked, not only the first: a mixed reply whose later
// result predates the offset field is a worker failure too.
func TestDecodeRejectsMixedResultsWithoutOffset(t *testing.T) {
	var control AnalyzeResult
	if err := DecodePayload(Frame{Payload: twoResultReply(`,"Basis":"always-remote","ResolutionOffset":-1`)}, &control); err != nil {
		t.Fatalf("complete two-result reply rejected: %v", err)
	}
	if len(control.Report.Results) != 2 {
		t.Fatalf("control decoded as %+v", control.Report)
	}
	var got AnalyzeResult
	if err := DecodePayload(Frame{Payload: twoResultReply(`,"Basis":"always-remote"`)}, &got); err == nil {
		t.Fatalf("reply whose second result has no offset decoded: %+v", got.Report)
	}
}

func TestDecodeRejectsResultWithNullOffset(t *testing.T) {
	var got AnalyzeResult
	if err := DecodePayload(Frame{Payload: resultReply(`,"Basis":"call-argument","ResolutionOffset":null`)}, &got); err == nil {
		t.Fatalf("reply with null offset decoded: %+v", got.Report)
	}
}

func TestDecodeRejectsResultWithoutBasis(t *testing.T) {
	var got AnalyzeResult
	if err := DecodePayload(Frame{Payload: resultReply(`,"ResolutionOffset":-1`)}, &got); err == nil {
		t.Fatalf("reply without basis decoded: %+v", got.Report)
	}
}

// Go's decoder matches keys case-insensitively and keeps the last one, so two
// spellings of one key would let a reply say two things at once.
func TestDecodeRejectsAmbiguousResultKeys(t *testing.T) {
	for _, keys := range []string{
		`,"Basis":"always-remote","ResolutionOffset":-1,"basis":"call-argument"`,
		`,"Basis":"call-argument","ResolutionOffset":-1,"resolutionoffset":5`,
	} {
		var got AnalyzeResult
		if err := DecodePayload(Frame{Payload: resultReply(keys)}, &got); err == nil {
			t.Errorf("ambiguous reply %s decoded: %+v", keys, got.Report)
		}
	}
}

func TestAnalyzeResultCarriesResolutionOffset(t *testing.T) {
	r := validResult()
	r.Basis = phptaint.BasisCallArgument
	r.ResolutionOffset = 5
	frame, err := EncodePayload("", AnalyzeResult{Report: analyzedWith(r)})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var got AnalyzeResult
	if err := DecodePayload(frame, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Report.Results) != 1 || got.Report.Results[0].ResolutionOffset != 5 ||
		got.Report.Results[0].Basis != phptaint.BasisCallArgument {
		t.Fatalf("round trip lost the resolution: %+v", got.Report)
	}
}
