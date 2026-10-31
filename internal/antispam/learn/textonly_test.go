package learn

import (
	"bytes"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"reflect"
	"strings"
	"testing"
)

const pdfMessage = "From: shop@example.com\n" +
	"Subject: offer\n" +
	"MIME-Version: 1.0\n" +
	"Content-Type: multipart/mixed; boundary=\"m\"\n" +
	"\n" +
	"--m\n" +
	"Content-Type: multipart/related; boundary=\"r\"\n" +
	"\n" +
	"--r\n" +
	"Content-Type: multipart/alternative; boundary=\"a\"\n" +
	"\n" +
	"--a\n" +
	"Content-Type: text/plain; charset=utf-8\n" +
	"Content-Transfer-Encoding: 8bit\n" +
	"\n" +
	"plain offer text\n" +
	"--a\n" +
	"Content-Type: text/html; charset=utf-8\n" +
	"Content-Transfer-Encoding: quoted-printable\n" +
	"\n" +
	"<p>html offer text</p>\n" +
	"--a--\n" +
	"--r\n" +
	"Content-Type: image/png\n" +
	"Content-Transfer-Encoding: base64\n" +
	"\n" +
	"iVBORw0KGgo=\n" +
	"--r--\n" +
	"--m\n" +
	"Content-Type: application/pdf; name=x.pdf\n" +
	"Content-Disposition: attachment; filename=x.pdf\n" +
	"Content-Transfer-Encoding: base64\n" +
	"\n" +
	"JVBERi0xLjQK\n" +
	"--m--\n"

// leaves parses msg and returns each leaf's content type and raw body.
func leaves(t *testing.T, msg []byte) (*mail.Message, [][2]string) {
	t.Helper()
	m, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("not a message: %v\n%s", err, msg)
	}
	var out [][2]string
	var walk func(ct string, body io.Reader)
	walk = func(ct string, body io.Reader) {
		mt, params, err := mime.ParseMediaType(ct)
		if err != nil {
			t.Fatalf("content type %q: %v", ct, err)
		}
		if !strings.HasPrefix(mt, "multipart/") {
			b, err := io.ReadAll(body)
			if err != nil {
				t.Fatalf("leaf body: %v", err)
			}
			out = append(out, [2]string{mt, string(b)})
			return
		}
		r := multipart.NewReader(body, params["boundary"])
		for {
			p, err := r.NextRawPart()
			if err == io.EOF {
				return
			}
			if err != nil {
				t.Fatalf("multipart body: %v", err)
			}
			walk(p.Header.Get("Content-Type"), p)
		}
	}
	walk(m.Header.Get("Content-Type"), m.Body)
	return m, out
}

func TestTextOnlyMessageDropsNonTextParts(t *testing.T) {
	got := textOnlyMessage([]byte(pdfMessage))
	m, parts := leaves(t, got)
	want := [][2]string{{"text/html", "<p>html offer text</p>"}, {"text/plain", "plain offer text"}}
	if !reflect.DeepEqual(parts, want) {
		t.Fatalf("leaves %q\n%s", parts, got)
	}
	if m.Header.Get("Subject") != "offer" || m.Header.Get("From") != "shop@example.com" {
		t.Fatalf("headers not kept:\n%s", got)
	}
	if strings.Contains(string(got), "JVBERi0") || strings.Contains(string(got), "iVBORw0") {
		t.Fatalf("non-text content kept:\n%s", got)
	}
	// The rebuilt message is stable, so a retried request stores the same body.
	if again := textOnlyMessage([]byte(pdfMessage)); !bytes.Equal(again, got) {
		t.Fatal("rebuild is not deterministic")
	}
}

func TestTextOnlyMessageOneTextPart(t *testing.T) {
	msg := "Subject: s\n" +
		"Content-Type: multipart/mixed; boundary=m\n\n" +
		"--m\nContent-Type: text/plain\n\nonly text\n" +
		"--m\nContent-Type: application/pdf\nContent-Disposition: attachment\n\nJVBERi0xLjQK\n" +
		"--m--\n"
	got := textOnlyMessage([]byte(msg))
	m, parts := leaves(t, got)
	if !reflect.DeepEqual(parts, [][2]string{{"text/plain", "only text"}}) || m.Header.Get("Subject") != "s" {
		t.Fatalf("got\n%s", got)
	}
}

func TestTextOnlyMessageKeepsMessagesWithNothingToDrop(t *testing.T) {
	for name, msg := range map[string]string{
		"text alternative": altMessage,
		"single text part": "Subject: s\nContent-Type: text/plain\n\nbody\n",
		"no content type":  "Subject: s\n\nbody\n",
		"no header break":  "fresh spam",
	} {
		if got := textOnlyMessage([]byte(msg)); string(got) != msg {
			t.Errorf("%s: changed to %q", name, got)
		}
	}
}

func TestTextOnlyMessageWithoutText(t *testing.T) {
	for name, msg := range map[string]string{
		"pdf body":   "Subject: s\nContent-Type: application/pdf\n\nJVBERi0xLjQK\n",
		"image only": "Subject: s\nContent-Type: multipart/mixed; boundary=m\n\n--m\nContent-Type: image/png\n\nx\n--m--\n",
		"text only attached": "Subject: s\nContent-Type: multipart/mixed; boundary=m\n\n" +
			"--m\nContent-Type: text/plain\nContent-Disposition: attachment\n\nx\n--m--\n",
	} {
		if got := textOnlyMessage([]byte(msg)); got != nil {
			t.Errorf("%s: got %q", name, got)
		}
	}
}

func TestEngineLearnsTextOnlyVersionOfReport(t *testing.T) {
	f := newAuditFixture(t)
	e := newTestEngine(t, f)
	text := textOnlyMessage([]byte(pdfMessage))
	// Only the text-only version is known to storage; inspecting the full
	// message fails, as rspamd does when an attachment adds its own hashes.
	f.storage.mu.Lock()
	f.storage.bodies[string(text)] = digest('t')
	f.storage.mu.Unlock()
	out, err := e.SubmitReport(context.Background(), Candidate{UID: 1002, Snapshot: []byte(pdfMessage)})
	if err != nil || len(out.Committed) != 1 {
		t.Fatalf("outcome %+v err %v", out, err)
	}
	c, _ := f.cluster(t, out.Committed[0])
	body, err := f.bodies.Read(c.ID, c.BodyLen, c.BodySHA)
	if err != nil || !bytes.Equal(body, text) || c.Anchor != digest('t') {
		t.Fatalf("cluster %+v body %q err %v", c, body, err)
	}
	if u := f.usage(t, 1002); u.BodyBytes != int64(len(text)) {
		t.Fatalf("usage %+v", u)
	}
}

func TestEngineReportWithoutTextIsNoDigest(t *testing.T) {
	f := newAuditFixture(t)
	e := newTestEngine(t, f)
	snap := []byte("Subject: s\nContent-Type: application/pdf\n\nJVBERi0xLjQK\n")
	out, err := e.SubmitReport(context.Background(), Candidate{UID: 1002, Snapshot: snap})
	if err != nil || out.Deferred || !reflect.DeepEqual(out.Skips, []Skip{{Reason: SkipNoDigest}}) {
		t.Fatalf("outcome %+v err %v", out, err)
	}
	if _, bodyInspects, _, _ := f.storage.native(); bodyInspects != 0 {
		t.Fatalf("%d body inspections", bodyInspects)
	}
}

func TestEngineForgetsWithTextOnlyVersion(t *testing.T) {
	f := newAuditFixture(t)
	e := newTestEngine(t, f)
	text := textOnlyMessage([]byte(pdfMessage))
	f.storage.mu.Lock()
	f.storage.bodies[string(text)] = digest('t')
	f.storage.mu.Unlock()
	snap := []byte(pdfMessage)
	mark := OperatorRequest{Action: ActionSpam, RequestID: "cccccccccccccccccccccccccccccccc", Snapshot: snap, SnapshotSHA: sha(snap)}
	if res, err := e.Operator(context.Background(), mark); err != nil || !res.ExitOK {
		t.Fatalf("mark %+v err %v", res, err)
	}
	forget := OperatorRequest{Action: ActionForget, RequestID: "dddddddddddddddddddddddddddddddd", Snapshot: snap, SnapshotSHA: sha(snap)}
	res, err := e.Operator(context.Background(), forget)
	if err != nil || !res.ExitOK || len(res.Clusters) != 1 || res.Clusters[0].Result != ResultForgotten {
		t.Fatalf("forget %+v err %v", res, err)
	}
}
