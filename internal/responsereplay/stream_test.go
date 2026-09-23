package responsereplay

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var streamTS = time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)

func writeRecording(t *testing.T, name string, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	data := []byte(strings.Join(lines, "\n") + "\n")
	if len(lines) == 0 {
		data = nil
	}
	if strings.HasSuffix(name, ".gz") {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		if _, err := zw.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		data = b.Bytes()
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func row(ts, check, severity, message, details, id string) string {
	return `{"v":1,"ts":"` + ts + `","finding_id":"` + id + `","severity":"` + severity + `","check":"` + check +
		`","message":"` + message + `","details":"` + details + `","hostname":"host-a1b2c3"}`
}

func TestReadFindingsKeepsReplayFieldsAndOrdinals(t *testing.T) {
	path := writeRecording(t, "stream.jsonl.gz",
		row("2026-09-08T10:00:01Z", "smtp_bruteforce", "CRITICAL", "SMTP brute force from 198.18.0.3", "Reason: x", "fid-3"),
		row("2026-09-08T10:00:00Z", "wp_login_bruteforce", "HIGH", "WordPress login brute force from 198.18.0.1", "d1", "fid-1"),
		row("2026-09-08T10:00:00Z", "smtp_bruteforce", "CRITICAL", "SMTP brute force from 198.18.0.2", "", "fid-2"),
	)
	rec, err := ReadFindings(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if rec.SHA256 != hex.EncodeToString(sum[:]) || rec.Rows != 3 || rec.Unstamped != 0 {
		t.Fatalf("provenance: %+v", rec)
	}
	want := []Finding{
		{At: streamTS.Add(time.Second), Check: "smtp_bruteforce", Severity: "CRITICAL", Message: "SMTP brute force from 198.18.0.3", Details: "Reason: x", FindingID: "fid-3", Ordinal: 1},
		{At: streamTS, Check: "wp_login_bruteforce", Severity: "HIGH", Message: "WordPress login brute force from 198.18.0.1", Details: "d1", FindingID: "fid-1", Ordinal: 2},
		{At: streamTS, Check: "smtp_bruteforce", Severity: "CRITICAL", Message: "SMTP brute force from 198.18.0.2", FindingID: "fid-2", Ordinal: 3},
	}
	if !reflect.DeepEqual(rec.Findings, want) {
		t.Fatalf("findings:\n got %+v\nwant %+v", rec.Findings, want)
	}
	batches := Batches(rec.Findings)
	if len(batches) != 2 || !batches[0].At.Equal(streamTS) || !batches[1].At.Equal(streamTS.Add(time.Second)) {
		t.Fatalf("batches: %+v", batches)
	}
	if got := []int{batches[0].Findings[0].Ordinal, batches[0].Findings[1].Ordinal, batches[1].Findings[0].Ordinal}; !reflect.DeepEqual(got, []int{2, 3, 1}) {
		t.Fatalf("batch order = %v", got)
	}
	// Batches sorts a copy: the recorded order stays as read.
	if rec.Findings[0].Ordinal != 1 {
		t.Fatal("Batches reordered its input")
	}
}

func TestBatchesGroupEqualInstantsAcrossOffsets(t *testing.T) {
	path := writeRecording(t, "offsets.jsonl",
		row("2026-09-08T13:00:00+03:00", "a", "HIGH", "m", "", "fid-1"),
		row("2026-09-08T10:00:00Z", "b", "HIGH", "m", "", "fid-2"),
		row("2026-09-08T05:00:00-05:00", "c", "HIGH", "m", "", "fid-3"),
	)
	rec, err := ReadFindings(path)
	if err != nil {
		t.Fatal(err)
	}
	batches := Batches(rec.Findings)
	if len(batches) != 1 || len(batches[0].Findings) != 3 {
		t.Fatalf("one instant split into %d batches", len(batches))
	}
	for i, f := range batches[0].Findings {
		if f.Ordinal != i+1 {
			t.Fatalf("tie order not by ordinal: %+v", batches[0].Findings)
		}
	}
	if len(Batches(nil)) != 0 {
		t.Fatal("empty stream produced batches")
	}
}

func TestReadFindingsCountsUnstampedRows(t *testing.T) {
	path := writeRecording(t, "unstamped.jsonl",
		row("2026-09-08T10:00:00Z", "a", "HIGH", "m", "", "fid-1"),
		row("0001-01-01T00:00:00Z", "b", "HIGH", "m", "", "fid-2"),
	)
	rec, err := ReadFindings(path)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Rows != 2 || rec.Unstamped != 1 || len(rec.Findings) != 1 || rec.Findings[0].Ordinal != 1 {
		t.Fatalf("unstamped row not counted apart: %+v", rec)
	}
}

func TestReadFindingsEmptyStream(t *testing.T) {
	rec, err := ReadFindings(writeRecording(t, "empty.jsonl"))
	sum := sha256.Sum256(nil)
	if err != nil || rec.Rows != 0 || len(rec.Findings) != 0 || rec.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("empty stream: %+v %v", rec, err)
	}
}

func TestReadFindingsRefusals(t *testing.T) {
	valid := row("2026-09-08T10:00:00Z", "a", "HIGH", "m", "", "fid-1")
	for name, tc := range map[string]struct {
		lines []string
		want  string
	}{
		"version":         {[]string{valid, strings.Replace(valid, `"v":1`, `"v":2`, 1)}, "recording line 2: " + string(errVersion)},
		"missing version": {[]string{strings.Replace(valid, `"v":1,`, ``, 1)}, "recording line 1: " + string(errMissingVersion)},
		"missing time":    {[]string{strings.Replace(valid, `"ts":"2026-09-08T10:00:00Z",`, ``, 1)}, "recording line 1: " + string(errMissingTime)},
		"unknown field":   {[]string{valid, strings.Replace(valid, `"v":1`, `"v":1,"alice":"x"`, 1)}, "recording line 2: " + string(errUnknownField)},
		"nested unknown":  {[]string{strings.Replace(valid, `"hostname"`, `"process":{"pid":1,"ppid":0,"uid":0,"alice":1},"hostname"`, 1)}, "recording line 1: " + string(errUnknownField)},
		"duplicate key":   {[]string{strings.Replace(valid, `"v":1`, `"v":1,"v":1`, 1)}, "recording line 1: " + string(errDuplicateKey)},
		"case alias":      {[]string{strings.Replace(valid, `"check":"a"`, `"CHECK":"a"`, 1)}, "recording line 1: " + string(errUnknownField)},
		"malformed":       {[]string{`{"v":1,`}, "recording line 1: " + string(errSyntax)},
		"trailing":        {[]string{valid + ` {}`}, "recording line 1: " + string(errTrailing)},
		"not an object":   {[]string{`[1]`}, "recording line 1: " + string(errNotObject)},
		"null":            {[]string{strings.Replace(valid, `"details":""`, `"details":null`, 1)}, "recording line 1: " + string(errNull)},
		"overlong line":   {[]string{valid, `{"message":"` + strings.Repeat("x", maxLineBytes) + `"}`}, "recording line 2: " + string(errLineTooLong)},
		"overlong text":   {[]string{strings.Replace(valid, `"message":"m"`, `"message":"`+strings.Repeat("x", maxTextBytes+1)+`"`, 1)}, "recording line 1: " + string(errTooLong)},
		"overlong scalar": {[]string{strings.Replace(valid, `"check":"a"`, `"check":"`+strings.Repeat("x", maxScalarBytes+1)+`"`, 1)}, "recording line 1: " + string(errTooLong)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ReadFindings(writeRecording(t, "alice-host.jsonl", tc.lines...))
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "alice") || strings.Contains(err.Error(), "fid-1") {
				t.Fatalf("error carries input: %v", err)
			}
		})
	}
}

func TestReadFindingsRefusesDamagedGzip(t *testing.T) {
	path := writeRecording(t, "stream.jsonl.gz", row("2026-09-08T10:00:00Z", "a", "HIGH", "m", "", "fid-1"))
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"truncated":      good[:len(good)-4],
		"bad checksum":   append(append(append([]byte{}, good[:len(good)-8]...), 0, 0, 0, 0), good[len(good)-4:]...),
		"trailing bytes": append(append([]byte{}, good...), "junk"...),
		"not gzip":       []byte("plain"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := ReadFindings(path)
			if !errors.Is(err, errGzip) {
				t.Fatalf("damaged gzip accepted: %v", err)
			}
		})
	}
	if _, err := ReadFindings(filepath.Join(t.TempDir(), "alice-missing.jsonl")); err == nil || err.Error() != "recording: "+string(errOpen) {
		t.Fatalf("missing file: %v", err)
	}
}

// Small inputs sort stably by accident; a large interleaved batch shows
// whether equal instants really keep their recorded order.
func TestBatchesKeepRecordedOrderWithinLargeBatches(t *testing.T) {
	var findings []Finding
	for i := range 200 {
		findings = append(findings, Finding{At: streamTS.Add(time.Duration(i%2) * time.Second), Ordinal: i + 1})
	}
	batches := Batches(findings)
	if len(batches) != 2 {
		t.Fatalf("%d batches", len(batches))
	}
	for _, b := range batches {
		for i := 1; i < len(b.Findings); i++ {
			if b.Findings[i-1].Ordinal > b.Findings[i].Ordinal {
				t.Fatalf("recorded order lost within %v: %d before %d", b.At, b.Findings[i-1].Ordinal, b.Findings[i].Ordinal)
			}
		}
	}
}
