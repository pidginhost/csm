package mime

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"os"
	"strings"
	"testing"
	"testing/iotest"
)

func TestTransferRecoveryStagesWholePayload(t *testing.T) {
	cases := []struct{ name, cte, encoded, want string }{
		{"partial padding", "base64", "YQ=", "a"},
		{"bare CR soft break", "quoted-printable", "PAY=\rLOAD", "PAYLOAD"},
		{"long quoted printable line", "quoted-printable", strings.Repeat("x", 5000) + "=00PAYLOAD", strings.Repeat("x", 5000) + "\x00PAYLOAD"},
		{"long control byte line", "quoted-printable", strings.Repeat("\x01", 2000) + "PAYLOAD", strings.Repeat("\x01", 2000) + "PAYLOAD"},
		{"split escape", "quoted-printable", strings.Repeat("x", 4095) + "=00PAYLOAD", strings.Repeat("x", 4095) + "\x00PAYLOAD"},
	}
	for _, tc := range cases {
		for _, single := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/single=%t", tc.name, single), func(t *testing.T) {
				var result *ExtractionResult
				if single {
					h, d := buildEximSpool(t, "application/octet-stream", tc.encoded)
					hdr, err := os.ReadFile(h)
					if err != nil {
						t.Fatal(err)
					}
					hdr = append(hdr, []byte(eximHdr(' ', "Content-Transfer-Encoding: "+tc.cte))...)
					if err = os.WriteFile(h, hdr, 0600); err != nil {
						t.Fatal(err)
					}
					limits := DefaultLimits()
					limits.TempDir = t.TempDir()
					result, err = ParseSpoolMessage(h, d, limits)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					result = parseSpoolWithCleanup(t, `multipart/mixed; boundary="outer"`, multipartWithEncodedPart("outer", tc.cte, tc.encoded))
				}
				requireSingleStagedPart(t, result, []byte(tc.want))
			})
		}
	}
}

func TestEncodedMultipartWrapper(t *testing.T) {
	inner := multipartWithEncodedPart("inner", "quoted-printable", "PAYLOAD=00tail")
	for _, cte := range []string{"quoted-printable", "base64"} {
		t.Run(cte, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString([]byte(inner))
			if cte == "quoted-printable" {
				var b bytes.Buffer
				w := quotedprintable.NewWriter(&b)
				if _, err := io.WriteString(w, inner); err != nil {
					t.Fatal(err)
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				encoded = b.String()
			}
			body := "--outer\r\nContent-Type: multipart/mixed; boundary=inner\r\nContent-Transfer-Encoding: " + cte + "\r\n\r\n" + encoded + "\r\n--outer--\r\n"
			result := parseSpoolWithCleanup(t, `multipart/mixed; boundary="outer"`, body)
			requireSingleStagedPart(t, result, []byte("PAYLOAD\x00tail"))
		})
	}
}

func TestBase64PaddingErrorIndependentOfReadSize(t *testing.T) {
	for _, size := range []int{1, 2, 3, 512, 32768} {
		for _, chunked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/chunked=%t", size, chunked), func(t *testing.T) {
				var source io.Reader = strings.NewReader("YWI=QUJD")
				if chunked {
					source = iotest.OneByteReader(source)
				}
				r := transferDecoder("base64", source)
				var got []byte
				buf := make([]byte, size)
				for {
					n, err := r.Read(buf)
					got = append(got, buf[:n]...)
					if err != nil {
						if err == io.EOF {
							t.Fatal("data after padding was not reported")
						}
						break
					}
				}
				if string(got) != "abABC" {
					t.Fatalf("decoded %q, want abABC", got)
				}
			})
		}
	}
}

// Thunderbird's mime_decode_base64_buffer processes every quartet, including
// those after padding. ZIP readers accept a leading prefix, so scanning only
// that prefix misses an archive the recipient can open.
// https://github.com/mozilla/releases-comm-central/blob/master/mailnews/mime/src/mimeenc.cpp
func TestBase64AfterPaddingStillExtractsArchive(t *testing.T) {
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	f, err := w.Create("payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(f, "scan this payload"); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	encoded := "YWI=" + base64.StdEncoding.EncodeToString(archive.Bytes())
	body := strings.ReplaceAll(multipartWithEncodedPart("B64", "base64", encoded), "payload.bin", "payload.zip")
	result := parseSpoolWithCleanup(t, `multipart/mixed; boundary="B64"`, body)
	if !result.Partial {
		t.Fatal("data after padding must remain partial")
	}
	if len(result.Parts) != 2 {
		t.Fatalf("Parts = %d, want archive and extracted payload", len(result.Parts))
	}
	got, err := os.ReadFile(result.Parts[1].TempPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "scan this payload" || !result.Parts[1].Nested {
		t.Fatalf("nested payload = %q, part = %+v", got, result.Parts[1])
	}
}
