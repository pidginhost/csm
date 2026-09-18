package mime

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime/quotedprintable"
	"os"
	"path/filepath"
	"testing"
)

// The Exim -H parser turns a spool header file into the envelope + RFC 5322
// header set that drives attachment extraction. The header bytes are populated
// from attacker-controlled message headers, so a crafted -H that panics the
// parser is a local DoS against the email-AV path. This target exercises the
// length+flag prefix stripping, folded continuations, and deleted-header
// handling against arbitrary input.
//
// Run locally with:
//
//	go test -run=xxx -fuzz=FuzzParseEximHeaderData -fuzztime=60s ./internal/mime/
func FuzzParseEximHeaderData(f *testing.F) {
	// Real-format golden fixtures as the primary seeds.
	for _, name := range []string{"simple-H", "multipart-H", "singlepart-H"} {
		if data, err := os.ReadFile(filepath.Join("testdata", name)); err == nil {
			f.Add(data)
		}
	}

	// Crafted edge cases.
	f.Add([]byte("id-H\nuser 1 1\n<u@example.com>\n0 0\n-local\n1\nr@example.com\n\n048F From: a@b\n028T To: c@d\n"))
	// 4-digit (variable-width) length prefix.
	f.Add([]byte("id-H\nuser 1 1\n<u@example.com>\n0 0\n\n1010  Subject: oversized header value\n"))
	// Deleted header ('*') plus a folded continuation.
	f.Add([]byte("id-H\nuser 1 1\n<u@example.com>\n0 0\n\n020* X-Old: gone\n039  Content-Type: multipart/mixed;\n\tboundary=\"b\"\n"))
	// Missing separator / truncated / garbage.
	f.Add([]byte("id-H\nuser 1 1\n"))
	f.Add([]byte("not an exim spool file at all"))
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic; parseEximHeaderData is fail-open by contract.
		env, hdrs := parseEximHeaderData(data)
		if env == nil || hdrs == nil {
			t.Fatal("parseEximHeaderData must return non-nil envelope and headers")
		}
	})
}

// transferDecoder decodes attacker-controlled attachment bodies. Two
// properties: arbitrary input never panics, and base64 with ignorable bytes
// spliced in decodes to exactly what clean base64 decodes to, and so does
// quoted-printable written by a conforming encoder.
func FuzzTransferDecoder(f *testing.F) {
	f.Add([]byte("SGVsbG8h"), []byte(" \t!"), uint8(3))
	f.Add([]byte("\x00\x01\x7f=ZZ=\r\n"), []byte("*"), uint8(0))
	f.Add([]byte(""), []byte(""), uint8(1))

	f.Fuzz(func(t *testing.T, data, junk []byte, stride uint8) {
		for _, cte := range []string{"base64", "quoted-printable", "7bit"} {
			_, _ = io.ReadAll(transferDecoder(cte, bytes.NewReader(data)))
		}

		encoded := base64.StdEncoding.EncodeToString(data)
		var spliced []byte
		step := int(stride%16) + 1
		for i := 0; i < len(encoded); i++ {
			if i%step == 0 {
				for _, b := range junk {
					if _, ok := base64Value(b); !ok && b != '=' {
						spliced = append(spliced, b)
					}
				}
			}
			spliced = append(spliced, encoded[i])
		}
		got, err := io.ReadAll(transferDecoder("base64", bytes.NewReader(spliced)))
		if err != nil {
			t.Fatalf("decode spliced base64: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("decoded %d bytes, want %d", len(got), len(data))
		}

		var qp bytes.Buffer
		w := quotedprintable.NewWriter(&qp)
		w.Binary = true
		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		got, err = io.ReadAll(transferDecoder("quoted-printable", &qp))
		if err != nil {
			t.Fatalf("decode quoted-printable: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("quoted-printable round trip changed %d bytes into %d", len(data), len(got))
		}
	})
}
