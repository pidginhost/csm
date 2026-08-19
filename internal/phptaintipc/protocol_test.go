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
		TotalResults:      3,
		EvidenceTruncated: true,
		Results: []phptaint.Result{
			{Source: "curl_exec", Sink: "eval", Confidence: phptaint.ConfidenceCertain, Identifiers: []string{"$p"}},
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
