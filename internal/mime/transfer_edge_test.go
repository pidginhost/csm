package mime

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"
)

func parseEncodedSpool(t *testing.T, contentType, cte, body string) *ExtractionResult {
	t.Helper()
	h, d := buildEximSpool(t, contentType, body)
	header, err := os.ReadFile(h)
	if err != nil {
		t.Fatal(err)
	}
	header = append(header, eximHdr(' ', "Content-Transfer-Encoding: "+cte)...)
	if err = os.WriteFile(h, header, 0600); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.TempDir = t.TempDir()
	result, err := ParseSpoolMessage(h, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestTopLevelEncodedMultipart(t *testing.T) {
	inner := multipartWithEncodedPart("inner", "quoted-printable", "PAYLOAD=00tail")
	for _, cte := range []string{"base64", "quoted-printable"} {
		t.Run(cte, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString([]byte(inner))
			if cte == "quoted-printable" {
				encoded = strings.ReplaceAll(inner, "=", "=3D")
				// Encode the delimiters too, so parsing the wire bytes fails.
				encoded = strings.ReplaceAll(encoded, "--inner", "=2D=2Dinner")
			}
			result := parseEncodedSpool(t, "multipart/mixed; boundary=inner", cte, encoded)
			requireSingleStagedPart(t, result, []byte("PAYLOAD\x00tail"))
		})
	}
}

func TestMultipartTransferFailurePreservesSiblings(t *testing.T) {
	for _, inner := range []string{
		"not a multipart body",
		"--inner\r\nbroken header\r\n\r\nignored\r\n--inner--\r\n",
	} {
		t.Run(inner, func(t *testing.T) {
			body := "--outer\r\nContent-Type: multipart/mixed; boundary=inner\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
				base64.StdEncoding.EncodeToString([]byte(inner)) + "\r\n" +
				multipartWithEncodedPart("outer", "base64", "UEFZTE9BRA==")
			result := parseSpoolWithCleanup(t, "multipart/mixed; boundary=outer", body)
			if !result.Partial || result.PartialReason == "" {
				t.Errorf("failed nested multipart was not reported: %+v", result)
			}
			requireStagedPrefix(t, result, []byte("PAYLOAD"))
		})
	}
}

func TestMultipartWrapperDecodeErrorIsReported(t *testing.T) {
	inner := multipartWithEncodedPart("inner", "base64", "UEFZTE9BRA==")
	for _, epilogue := range []string{"", strings.Repeat(" ", 10002)} {
		for _, topLevel := range []bool{false, true} {
			t.Run(fmt.Sprintf("epilogue=%d/top=%t", len(epilogue), topLevel), func(t *testing.T) {
				// A complete MIME closing delimiter may hide the decoder's error,
				// even when it occurs beyond the multipart reader's lookahead.
				encoded := base64.StdEncoding.EncodeToString([]byte(inner + epilogue))
				if !strings.HasSuffix(encoded, "=") {
					t.Fatal("fixture must have padding before the extra data")
				}
				encoded += "QQ=="
				var result *ExtractionResult
				if topLevel {
					result = parseEncodedSpool(t, "multipart/mixed; boundary=inner", "base64", encoded)
				} else {
					body := "--outer\r\nContent-Type: multipart/mixed; boundary=inner\r\nContent-Transfer-Encoding: base64\r\n\r\n" + encoded + "\r\n--outer--\r\n"
					result = parseSpoolWithCleanup(t, "multipart/mixed; boundary=outer", body)
				}
				if !result.Partial || !strings.Contains(result.PartialReason, "decode") {
					t.Errorf("wrapper decode error was not reported: %+v", result)
				}
				requireStagedPrefix(t, result, []byte("PAYLOAD"), []byte("PAYLOAD"))
			})
		}
	}
}

func TestAmbiguousBase64PaddingStagesAlphabetInterpretation(t *testing.T) {
	want := transferPayload()
	encoded := base64.StdEncoding.EncodeToString(want)
	for _, body := range []string{"=" + encoded, encoded[:1] + "=" + encoded[1:]} {
		for _, single := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/single=%t", body[:4], single), func(t *testing.T) {
				var result *ExtractionResult
				if single {
					result = parseEncodedSpool(t, "application/octet-stream", "base64", body)
				} else {
					result = parseSpoolWithCleanup(t, "multipart/mixed; boundary=outer", multipartWithEncodedPart("outer", "base64", body))
				}
				if !result.Partial {
					t.Error("ambiguous encoding was not reported")
				}
				for _, part := range result.Parts {
					got, err := os.ReadFile(part.TempPath)
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Equal(got, want) {
						return
					}
				}
				t.Fatal("alphabet interpretation of the attachment was not staged")
			})
		}
	}
}

func TestTruncatedMultipartFlushesDecodedTail(t *testing.T) {
	for _, tc := range []struct{ cte, encoded, want string }{
		{"base64", "YQ", "a"},
		{"base64", "YWI", "ab"},
		{"quoted-printable", "PAYLOAD=", "PAYLOAD="},
		{"quoted-printable", "PAYLOAD=A", "PAYLOAD=A"},
	} {
		t.Run(tc.encoded, func(t *testing.T) {
			body := "--outer\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: " + tc.cte + "\r\n\r\n" + tc.encoded
			result := parseSpoolWithCleanup(t, "multipart/mixed; boundary=outer", body)
			if !result.Partial {
				t.Error("truncated MIME body was not reported")
			}
			requireStagedPrefix(t, result, []byte(tc.want))
		})
	}
}

type terminalErrorReader struct {
	io.Reader
	err error
}

func (r terminalErrorReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		err = r.err
	}
	return n, err
}

func TestTransferFlushesBeforeSourceError(t *testing.T) {
	readErr := errors.New("source failed")
	for _, tc := range []struct{ cte, encoded, want string }{
		{"base64", "YQ", "a"},
		{"quoted-printable", "=A", "=A"},
	} {
		for _, simultaneous := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/together=%t", tc.cte, simultaneous), func(t *testing.T) {
				var src io.Reader = strings.NewReader(tc.encoded)
				if simultaneous {
					src = iotest.DataErrReader(src)
				}
				got, err := io.ReadAll(transferDecoder(tc.cte, terminalErrorReader{src, readErr}))
				if string(got) != tc.want || !errors.Is(err, readErr) {
					t.Fatalf("got %q, %v; want %q, source error", got, err, tc.want)
				}
			})
		}
	}
}

// Thunderbird consumes '=' as a slot in a quartet, including misplaced
// padding. Resetting the quartet at '=' shifts the following ZIP bytes.
// https://github.com/mozilla/releases-comm-central/blob/master/mailnews/mime/src/mimeenc.cpp
func TestMisplacedBase64PaddingPreservesArchive(t *testing.T) {
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	f, err := w.Create("payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(f, "scan this payload"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"=AAA", "A=AA", "AA=A", "===="} {
		t.Run(prefix, func(t *testing.T) {
			encoded := prefix + base64.StdEncoding.EncodeToString(archive.Bytes())
			body := strings.ReplaceAll(multipartWithEncodedPart("outer", "base64", encoded), "payload.bin", "payload.zip")
			result := parseSpoolWithCleanup(t, "multipart/mixed; boundary=outer", body)
			if !result.Partial {
				t.Error("misplaced padding was not reported")
			}
			wantParts := 3 // two interpretations and the quartet view's ZIP member
			if prefix == "====" {
				wantParts = 4 // both interpretations are readable ZIPs
			}
			if len(result.Parts) != wantParts {
				t.Fatalf("Parts = %d, want %d", len(result.Parts), wantParts)
			}
			got, err := os.ReadFile(result.Parts[1].TempPath)
			if err != nil || string(got) != "scan this payload" || !result.Parts[1].Nested {
				t.Fatalf("archive member = %q, err = %v, part = %+v", got, err, result.Parts[1])
			}
		})
	}
}

func TestSinglePartDecodeVariantsRespectTotalLimit(t *testing.T) {
	h, d := buildEximSpool(t, "application/octet-stream", "=UEFZTE9BRA==")
	header, err := os.ReadFile(h)
	if err != nil {
		t.Fatal(err)
	}
	header = append(header, eximHdr(' ', "Content-Transfer-Encoding: base64")...)
	if err = os.WriteFile(h, header, 0600); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.TempDir = t.TempDir()
	limits.MaxExtractionSize = 10
	result, err := ParseSpoolMessage(h, d, limits)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, part := range result.Parts {
		total += part.Size
	}
	if total > limits.MaxExtractionSize || !result.Partial {
		t.Fatalf("staged %d bytes with limit %d; partial=%t", total, limits.MaxExtractionSize, result.Partial)
	}
}

func TestNestedDecodeVariantsHaveMessageBudget(t *testing.T) {
	boundary := "leaf"
	body := multipartWithEncodedPart(boundary, "7bit", "PAYLOAD")
	for i := 0; i < 6; i++ {
		outer := fmt.Sprintf("layer%d", i)
		encoded := base64.StdEncoding.EncodeToString([]byte(body)) + "=AAA"
		body = "--" + outer + "\r\nContent-Type: multipart/mixed; boundary=" + boundary + "\r\nContent-Transfer-Encoding: base64\r\n\r\n" + encoded + "\r\n--" + outer + "--\r\n"
		boundary = outer
	}
	result := parseSpoolWithCleanup(t, "multipart/mixed; boundary="+boundary, body)
	if len(result.Parts) == 0 || len(result.Parts) > 17 || !result.Partial {
		t.Fatalf("ambiguous wrappers multiplied work beyond the message budget: %d parts, partial=%t", len(result.Parts), result.Partial)
	}
	for _, part := range result.Parts {
		got, err := os.ReadFile(part.TempPath)
		if err != nil || string(got) != "PAYLOAD" {
			t.Fatalf("decoded leaf = %q, %v", got, err)
		}
	}
}

// A client that stops at the first padded quartet sees a valid ZIP. Appending
// a large decoded suffix moves its directory beyond ZIP readers' search window.
func TestBase64PaddedPrefixStillExtractsArchive(t *testing.T) {
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	f, err := w.Create("payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(f, "scan this payload"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// ZIP readers accept a short trailing suffix. Choose a length requiring
	// padding without relying on the compressed member's exact size.
	data := archive.Bytes()
	for len(data)%3 == 0 {
		data = append(data, 0)
	}
	encoded := base64.StdEncoding.EncodeToString(data) + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 70000))
	body := strings.ReplaceAll(multipartWithEncodedPart("outer", "base64", encoded), "payload.bin", "payload.zip")
	result := parseSpoolWithCleanup(t, "multipart/mixed; boundary=outer", body)
	if !result.Partial {
		t.Error("data after padding was not reported")
	}
	for _, part := range result.Parts {
		if !part.Nested {
			continue
		}
		got, err := os.ReadFile(part.TempPath)
		if err != nil || string(got) != "scan this payload" {
			t.Fatalf("archive member = %q, %v", got, err)
		}
		return
	}
	t.Fatal("padded-prefix ZIP member was not staged")
}
