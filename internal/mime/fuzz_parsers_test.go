package mime

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/base64"
	"io"
	"mime/quotedprintable"
	"os"
	"path/filepath"
	"testing"
	"testing/iotest"

	"github.com/pidginhost/csm/internal/zipdir"
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

func FuzzTarMetadataSize(f *testing.F) {
	f.Add([]byte("00000000013\x00"))
	f.Add([]byte("000\x00ignored!"))
	f.Add([]byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0})
	f.Add([]byte("-00000000001"))
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "member", Mode: 0o644, Format: tar.FormatGNU}); err != nil {
		f.Fatal(err)
	}
	header := bytes.Clone(buf.Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		var field [12]byte
		copy(field[:], data)
		raw := bytes.Clone(header)
		copy(raw[124:136], field[:])
		setTarChecksum(raw)
		hdr, wantErr := tar.NewReader(bytes.NewReader(raw)).Next()
		got, err := tarMetadataSize(field[:])
		if (wantErr == nil) != (err == nil) || (err == nil && got != hdr.Size) {
			t.Fatalf("size %x: got %d, %v; tar header=%+v, %v", field, got, err, hdr, wantErr)
		}
	})
}

func FuzzArchiveWalkBounds(f *testing.F) {
	f.Add([]byte(""))
	f.Add(make([]byte, 1024))
	metadata := rawTarMember(f, tar.TypeXHeader, []byte("26 GNU.sparse.numblocks=1\n22 GNU.sparse.map=0,0\n27 GNU.sparse.size=1048576\n"))
	sparse := append(append([]byte(nil), metadata...), rawTarMember(f, tar.TypeReg, nil)...)
	f.Add(append(sparse, make([]byte, 1024)...))
	f.Add(append(rawTarMember(f, tar.TypeReg, []byte("body")), make([]byte, 1024)...))
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	if _, err := zw.Create("empty"); err != nil {
		f.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		f.Fatal(err)
	}
	f.Add(zb.Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		var spent int64
		budget := &budgetReader{r: bytes.NewReader(data), spent: &spent, limit: 4096}
		walk := &tarWalkReader{r: budget, walkCap: 10}
		tr := tar.NewReader(walk)
		for {
			hdr, err := tr.Next()
			if err != nil || budget.err != nil {
				break
			}
			if err = walk.setMember(hdr); err != nil {
				break
			}
			if _, err = io.Copy(io.Discard, io.LimitReader(tr, 4097)); err != nil {
				break
			}
		}
		if spent > 4097 || walk.walked > 10 {
			t.Fatalf("tar exceeded bounds: bytes=%d headers=%d", spent, walk.walked)
		}

		r := bytes.NewReader(data)
		dir, err := zipdir.Read(r, int64(len(data)), 4096)
		if err != nil || validateZIPDirectory(r, int64(len(data)), dir, 10) != nil {
			return
		}
		zr, err := zip.NewReader(r, int64(len(data)))
		if err == nil && (len(zr.File) > 10 || uint64(len(zr.File)) != dir.Records) {
			t.Fatalf("zip preflight disagrees with reader: declared=%d files=%d", dir.Records, len(zr.File))
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
			got, err := io.ReadAll(transferDecoder(cte, bytes.NewReader(data)))
			chunked, chunkErr := io.ReadAll(transferDecoder(cte, iotest.OneByteReader(bytes.NewReader(data))))
			if !bytes.Equal(got, chunked) || (err == nil) != (chunkErr == nil) {
				t.Fatalf("%s decoding depends on input chunk size", cte)
			}
		}
		readers, err := transferReaders("base64", bytes.NewReader(data), &ExtractionResult{})
		if err != nil || len(readers) < 1 || len(readers) > 3 {
			t.Fatalf("unexpected transfer readers: count=%d, error=%v", len(readers), err)
		}
		for _, reader := range readers {
			decoded, _ := io.ReadAll(reader)
			if len(decoded) > len(data) {
				t.Fatal("base64 interpretation expanded the input")
			}
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
