package mime

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// transferPayload is binary so a decoder that drops, shifts, or adds bytes
// cannot produce the same staged file by accident.
func transferPayload() []byte {
	p := make([]byte, 300)
	for i := range p {
		p[i] = byte(i * 7)
	}
	return p
}

func multipartWithEncodedPart(boundary, cte, encoded string) string {
	return "--" + boundary + "\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"See attachment.\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: application/octet-stream; name=\"payload.bin\"\r\n" +
		"Content-Disposition: attachment; filename=\"payload.bin\"\r\n" +
		"Content-Transfer-Encoding: " + cte + "\r\n\r\n" +
		encoded + "\r\n" +
		"--" + boundary + "--\r\n"
}

func parseSpoolWithCleanup(t *testing.T, contentType, body string) *ExtractionResult {
	t.Helper()
	hPath, dPath := buildEximSpool(t, contentType, body)
	limits := DefaultLimits()
	limits.TempDir = t.TempDir()
	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	t.Cleanup(func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	})
	return result
}

func requireSingleStagedPart(t *testing.T, result *ExtractionResult, want []byte) {
	t.Helper()
	if result.Partial {
		t.Fatalf("Partial = true (%q), want the attachment staged whole", result.PartialReason)
	}
	if len(result.Parts) != 1 {
		t.Fatalf("Parts = %d, want 1", len(result.Parts))
	}
	got, err := os.ReadFile(result.Parts[0].TempPath)
	if err != nil {
		t.Fatalf("read staged part: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("staged %d bytes that differ from the %d-byte payload", len(got), len(want))
	}
}

// RFC 2045 section 6.8: characters outside the base64 alphabet are ignored.
// Mail clients decode such bodies, so a strict decoder that gives up leaves
// the attachment delivered without ever being scanned.
func TestMultipartBase64IgnoresCharactersOutsideAlphabet(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(transferPayload())
	cases := map[string]string{
		"space inside line":   encoded[:40] + " " + encoded[40:120] + " " + encoded[120:],
		"tab and trailing ws": encoded[:76] + " \t\r\n" + encoded[76:152] + "\t\r\n" + encoded[152:],
		"stray punctuation":   encoded[:10] + "!" + encoded[10:200] + "*~" + encoded[200:],
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			result := parseSpoolWithCleanup(t, `multipart/mixed; boundary="B64"`,
				multipartWithEncodedPart("B64", "base64", body))
			requireSingleStagedPart(t, result, transferPayload())
		})
	}
}

func TestMultipartBase64WithoutFinalPaddingIsStaged(t *testing.T) {
	payload := transferPayload()[:299]
	encoded := strings.TrimRight(base64.StdEncoding.EncodeToString(payload), "=")
	if len(encoded)%4 == 0 {
		t.Fatal("fixture must end in an incomplete quantum")
	}
	result := parseSpoolWithCleanup(t, `multipart/mixed; boundary="B64"`,
		multipartWithEncodedPart("B64", "base64", encoded))
	requireSingleStagedPart(t, result, payload)
}

// A raw control byte in a quoted-printable body is malformed, but readers
// pass it through; the scanner must see the same bytes.
func TestMultipartQuotedPrintableKeepsRawControlBytes(t *testing.T) {
	result := parseSpoolWithCleanup(t, `multipart/mixed; boundary="QP"`,
		multipartWithEncodedPart("QP", "quoted-printable", "head\x01mid=3Dtail\x7f"))
	requireSingleStagedPart(t, result, []byte("head\x01mid=tail\x7f"))
}

func TestSinglePartBase64IgnoresCharactersOutsideAlphabet(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(transferPayload())
	hPath, dPath := buildEximSpool(t, "application/octet-stream; name=\"payload.bin\"", "")
	// buildEximSpool has no per-message transfer encoding header, so add it.
	h, err := os.ReadFile(hPath)
	if err != nil {
		t.Fatal(err)
	}
	h = append(h, []byte(eximHdr(' ', "Content-Transfer-Encoding: base64"))...)
	if err = os.WriteFile(hPath, h, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := os.ReadFile(dPath)
	if err != nil {
		t.Fatal(err)
	}
	d = append(d, []byte(encoded[:50]+" "+encoded[50:]+"\r\n")...)
	if err = os.WriteFile(dPath, d, 0o644); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.TempDir = t.TempDir()
	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	t.Cleanup(func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	})
	requireSingleStagedPart(t, result, transferPayload())
}

// Data after base64 padding is malformed. Clients such as Thunderbird keep
// decoding each quartet, so the scanners get every decoded byte, and the part
// is still reported as a decode failure rather than a staging or size problem.
func TestMultipartBase64DecodeFailureNamesDecoding(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("ab")) + base64.StdEncoding.EncodeToString(transferPayload())
	result := parseSpoolWithCleanup(t, `multipart/mixed; boundary="B64"`,
		multipartWithEncodedPart("B64", "base64", encoded))
	if !result.Partial {
		t.Fatal("Partial = false, want true for data after padding")
	}
	if !strings.Contains(result.PartialReason, "could not decode attachment") {
		t.Fatalf("PartialReason = %q, want a decode failure", result.PartialReason)
	}
	requireStagedPrefix(t, result, append([]byte("ab"), transferPayload()...), []byte("ab"))
}

// A trailing character that completes no byte makes the decoder fail after
// it has produced the whole payload. Clients show that payload, so the
// scanners must get it too; dropping the part would let one appended
// character deliver an attachment unscanned.
func TestMultipartBase64DanglingCharacterStillScansPayload(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(transferPayload()) + "Q"
	result := parseSpoolWithCleanup(t, `multipart/mixed; boundary="B64"`,
		multipartWithEncodedPart("B64", "base64", encoded))
	if !result.Partial {
		t.Fatal("Partial = false, want the decode failure reported")
	}
	requireStagedPrefix(t, result, transferPayload())
}

func requireStagedPrefix(t *testing.T, result *ExtractionResult, want []byte, alternatives ...[]byte) {
	t.Helper()
	wants := append([][]byte{want}, alternatives...)
	if len(result.Parts) != len(wants) {
		t.Fatalf("Parts = %d, want %d decoded interpretations staged for scanning", len(result.Parts), len(wants))
	}
	for i, want := range wants {
		got, err := os.ReadFile(result.Parts[i].TempPath)
		if err != nil {
			t.Fatalf("read staged part: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("interpretation %d: staged %d bytes, want the %d decoded bytes", i, len(got), len(want))
		}
	}
}

func TestSinglePartBase64DecodeFailureNamesDecoding(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("ab")) + base64.StdEncoding.EncodeToString(transferPayload())
	hPath, dPath := buildEximSpool(t, "application/octet-stream; name=\"payload.bin\"", encoded+"\r\n")
	h, err := os.ReadFile(hPath)
	if err != nil {
		t.Fatal(err)
	}
	h = append(h, []byte(eximHdr(' ', "Content-Transfer-Encoding: base64"))...)
	if err = os.WriteFile(hPath, h, 0o644); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.TempDir = t.TempDir()
	result, err := ParseSpoolMessage(hPath, dPath, limits)
	if err != nil {
		t.Fatalf("ParseSpoolMessage: %v", err)
	}
	if !result.Partial {
		t.Fatal("Partial = false, want true for data after padding")
	}
	if !strings.Contains(result.PartialReason, "could not decode single-part attachment") {
		t.Fatalf("PartialReason = %q, want a decode failure", result.PartialReason)
	}
	t.Cleanup(func() {
		for _, p := range result.Parts {
			os.Remove(p.TempPath)
		}
	})
	requireStagedPrefix(t, result, append([]byte("ab"), transferPayload()...), []byte("ab"))
}
