package parseworker

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/workerproc"
)

type mailPart struct {
	name string
	data []byte
}

func eximHeaderLine(flag byte, header string) string {
	return fmt.Sprintf("%d%c %s\n", len(header)+1, flag, header)
}

// spoolPair writes an Exim -H/-D pair: a multipart body carrying parts in
// order, base64-encoded. Addresses are example.com only.
func spoolPair(t *testing.T, subject string, to []string, parts ...mailPart) (*os.File, *os.File) {
	t.Helper()
	dir := t.TempDir()
	const id = "1Test0-0000000ABCd-1X2Y"
	const boundary = "csm-boundary"
	header := id + "-H\n" + "cpuser 1000 1000\n" + "<sender@example.com>\n" + "1777409000 0\n" + "-received_protocol esmtp\n" +
		"1\n" + "user@example.com\n" + "\n" +
		eximHeaderLine('F', "From: sender@example.com") +
		eximHeaderLine('T', "To: "+strings.Join(to, ", ")) +
		eximHeaderLine(' ', "Subject: "+subject) +
		eximHeaderLine(' ', "MIME-Version: 1.0") +
		eximHeaderLine(' ', "Content-Type: multipart/mixed; boundary="+boundary)
	var body strings.Builder
	body.WriteString(id + "-D\n--" + boundary + "\r\nContent-Type: text/plain\r\n\r\nhi\r\n")
	for _, p := range parts {
		fmt.Fprintf(&body, "--%s\r\nContent-Type: application/octet-stream; name=%q\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n",
			boundary, p.name, base64.StdEncoding.EncodeToString(p.data))
	}
	body.WriteString("--" + boundary + "--\r\n")
	open := func(name, data string) *os.File {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	return open(id+"-H", header), open(id+"-D", body.String())
}

func extractRequest(t *testing.T) workerproc.Frame {
	t.Helper()
	payload, err := json.Marshal(ExtractArgs{MaxAttachmentSize: 25 << 20, MaxArchiveDepth: 1, MaxArchiveFiles: 50, MaxExtractionSize: 100 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return workerproc.Frame{Op: OpExtractMessage, Payload: payload}
}

func extractVia(t *testing.T, header, body *os.File) (ExtractResult, []*os.File) {
	t.Helper()
	conn := servePair(t)
	if err := workerproc.SendFrame(conn, extractRequest(t), []*os.File{header, body}, WorkerLimits.MaxFrameBytes); err != nil {
		t.Fatal(err)
	}
	reply, fds, err := workerproc.ReceiveFrame(conn, ExtractLimits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, f := range fds {
			_ = f.Close()
		}
	})
	if reply.Error != "" {
		t.Fatalf("worker error: %s", reply.Error)
	}
	var res ExtractResult
	if err := json.Unmarshal(reply.Payload, &res); err != nil {
		t.Fatal(err)
	}
	return res, fds
}

func readPart(t *testing.T, f *os.File, size int64) []byte {
	t.Helper()
	b, err := io.ReadAll(io.NewSectionReader(f, 0, size))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExtractReturnsSealedPartMemfds(t *testing.T) {
	h, d := spoolPair(t, "invoice", []string{"user@example.com"}, mailPart{"a.pdf", []byte("first part")}, mailPart{"b.doc", []byte("second")})
	res, fds := extractVia(t, h, d)
	if len(res.Parts) != 2 || len(fds) != 2 || res.Partial {
		t.Fatalf("parts %d fds %d partial %v (%s)", len(res.Parts), len(fds), res.Partial, res.PartialReason)
	}
	for i, want := range []string{"first part", "second"} {
		if err := checkSealed(fds[i]); err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
		st, err := fds[i].Stat()
		if err != nil || st.Size() != res.Parts[i].Size || string(readPart(t, fds[i], res.Parts[i].Size)) != want {
			t.Fatalf("part %d: %+v size %v", i, res.Parts[i], st)
		}
	}
	if res.Parts[0].Filename != "a.pdf" || res.Subject != "invoice" || res.From != "sender@example.com" {
		t.Fatalf("metadata %+v", res)
	}
}

func zipWithContent(t *testing.T, files ...mailPart) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(f.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractZipMembersAreParts(t *testing.T) {
	archive := zipWithContent(t, mailPart{"m1.txt", []byte("one")}, mailPart{"m2.txt", []byte("two")})
	h, d := spoolPair(t, "zip", []string{"user@example.com"}, mailPart{"files.zip", archive})
	res, fds := extractVia(t, h, d)
	got := map[string]string{}
	for i, p := range res.Parts {
		if p.Nested && p.ArchiveName == "files.zip" {
			got[p.Filename] = string(readPart(t, fds[i], p.Size))
		}
	}
	if len(fds) != len(res.Parts) || len(res.Parts) != 3 || got["m1.txt"] != "one" || got["m2.txt"] != "two" {
		t.Fatalf("parts %+v members %v", res.Parts, got)
	}
}

func TestExtractTooManyPartsIsPartial(t *testing.T) {
	var parts []mailPart
	for i := range 205 {
		parts = append(parts, mailPart{fmt.Sprintf("p%03d.bin", i), []byte{byte(i%250 + 1)}})
	}
	h, d := spoolPair(t, "many", []string{"user@example.com"}, parts...)
	res, fds := extractVia(t, h, d)
	if len(res.Parts) != MaxParts || len(fds) != MaxParts || !res.Partial || res.PartialReason != "message has more than 200 attachments" {
		t.Fatalf("parts %d fds %d partial %v reason %q", len(res.Parts), len(fds), res.Partial, res.PartialReason)
	}
	if string(readPart(t, fds[199], 1)) != string([]byte{200}) {
		t.Fatal("parts out of order")
	}
}

func TestExtractDropsEmptyParts(t *testing.T) {
	h, d := spoolPair(t, "empty", []string{"user@example.com"}, mailPart{"empty.bin", nil}, mailPart{"full.bin", []byte("x")})
	res, fds := extractVia(t, h, d)
	if len(res.Parts) != 1 || len(fds) != 1 || res.Parts[0].Filename != "full.bin" {
		t.Fatalf("parts %+v", res.Parts)
	}
}

func TestExtractBoundsStrings(t *testing.T) {
	var to []string
	for i := range 150 {
		to = append(to, fmt.Sprintf("u%d@example.com", i))
	}
	h, d := spoolPair(t, strings.Repeat("s", 2000), to, mailPart{strings.Repeat("n", 400) + ".pdf", []byte("x")})
	res, _ := extractVia(t, h, d)
	if len(res.Parts) != 1 || len(res.Parts[0].Filename) > 255 || len(res.Subject) > 998 || len(res.To) != 100 {
		t.Fatalf("filename %d subject %d to %d", len(res.Parts[0].Filename), len(res.Subject), len(res.To))
	}
	for _, s := range append([]string{res.Subject, res.Parts[0].Filename}, res.To...) {
		if !utf8.ValidString(s) || len(s) > 998 {
			t.Fatalf("unbounded or invalid string %q", s)
		}
	}
}

func TestExtractCapsEncryptedEntries(t *testing.T) {
	res := ExtractResult{}
	entries := make([]EncryptedEntry, MaxEncryptedEntries+5)
	capEncrypted(&res, entries, 2)
	if len(res.EncryptedEntries) != MaxEncryptedEntries || res.EncryptedEntriesOmitted != 7 {
		t.Fatalf("entries %d omitted %d", len(res.EncryptedEntries), res.EncryptedEntriesOmitted)
	}
}

func TestExtractRequiresTwoRegularDescriptors(t *testing.T) {
	conn := servePair(t)
	h, d := spoolPair(t, "x", []string{"user@example.com"}, mailPart{"a.bin", []byte("x")})
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	for _, fds := range [][]*os.File{{h}, {h, r}} {
		if err := workerproc.SendFrame(conn, extractRequest(t), fds, WorkerLimits.MaxFrameBytes); err != nil {
			t.Fatal(err)
		}
		reply, got, err := workerproc.ReceiveFrame(conn, ExtractLimits)
		if err != nil || reply.Error == "" || len(got) != 0 {
			t.Fatalf("%d descriptors: reply %+v err %v", len(fds), reply, err)
		}
	}
	// The loop goes on.
	if err := workerproc.SendFrame(conn, extractRequest(t), []*os.File{h, d}, WorkerLimits.MaxFrameBytes); err != nil {
		t.Fatal(err)
	}
	if reply, got, err := workerproc.ReceiveFrame(conn, ExtractLimits); err != nil || reply.Error != "" || len(got) != 1 {
		t.Fatalf("after refusals: %+v %d %v", reply, len(got), err)
	}
}

func TestExtractCorruptZipIsPartial(t *testing.T) {
	h, d := spoolPair(t, "bad", []string{"user@example.com"}, mailPart{"ok.txt", []byte("fine")}, mailPart{"bad.zip", []byte("PK\x03\x04 not a zip at all, long enough to matter")})
	res, fds := extractVia(t, h, d)
	if !res.Partial || res.PartialReason == "" || len(fds) != len(res.Parts) || len(res.Parts) < 1 || res.Parts[0].Filename != "ok.txt" {
		t.Fatalf("partial %v reason %q parts %+v", res.Partial, res.PartialReason, res.Parts)
	}
}

// MAIL-02: the worker gets descriptors, never a path to open.
func TestExtractArgsCarryNoPath(t *testing.T) {
	ty := reflect.TypeOf(ExtractArgs{})
	for i := range ty.NumField() {
		if ty.Field(i).Type.Kind() == reflect.String {
			t.Fatalf("ExtractArgs.%s is a string: requests must not carry paths", ty.Field(i).Name)
		}
	}
}

// The reply must fit the frame however the strings encode: '"' doubles in
// JSON, and '<' would grow sixfold with HTML escaping left on.
func TestExtractWorstCaseReplyFits(t *testing.T) {
	for _, ch := range []string{`"`, "<"} {
		name := strings.Repeat(ch, maxNameBytes)
		header := strings.Repeat(ch, maxHeaderBytes)
		res := ExtractResult{Partial: true, PartialReason: strings.Repeat(ch, maxIncomplete), From: header, Subject: header, Direction: "inbound"}
		for range MaxParts {
			res.Parts = append(res.Parts, ExtractPart{Filename: name, ContentType: name, Size: 1 << 40, Nested: true, ArchiveName: name})
		}
		for range maxRecipients {
			res.To = append(res.To, header)
		}
		for range MaxEncryptedEntries {
			res.EncryptedEntries = append(res.EncryptedEntries, EncryptedEntry{ArchiveName: name, Filename: name})
		}
		res.EncryptedEntriesOmitted = 1 << 30
		var frame bytes.Buffer
		if err := workerproc.WriteFrame(&frame, extractResult(res), WorkerLimits.MaxFrameBytes); err != nil {
			t.Fatalf("worst-case reply of %q does not fit its frame: %v", ch, err)
		}
	}
}

func TestExtractCleansHeaderStrings(t *testing.T) {
	if got := cleanText("\x1bA\xffB\t<", 10); got != "A\uFFFDB\t<" {
		t.Fatalf("cleanText = %q", got)
	}
	h, d := spoolPair(t, "<b>red</b>", []string{"user@example.com"}, mailPart{"a.bin", []byte("x")})
	conn := servePair(t)
	if err := workerproc.SendFrame(conn, extractRequest(t), []*os.File{h, d}, WorkerLimits.MaxFrameBytes); err != nil {
		t.Fatal(err)
	}
	reply, fds, err := workerproc.ReceiveFrame(conn, ExtractLimits)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fds {
		_ = f.Close()
	}
	var res ExtractResult
	if err := json.Unmarshal(reply.Payload, &res); err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(res.Subject) || res.Subject != "<b>red</b>" {
		t.Fatalf("subject %q", res.Subject)
	}
	if !bytes.Contains(reply.Payload, []byte("<b>red")) {
		t.Fatalf("reply escaped HTML: %s", reply.Payload)
	}
	if err := checkExtract(reply.Payload, nil, testLimits(), &ExtractResult{}); err != nil && !strings.Contains(err.Error(), "descriptors") {
		t.Fatalf("daemon refused the cleaned strings: %v", err)
	}
}
