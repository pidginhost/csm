package learn

import (
	"bytes"
	"net/mail"
	"strings"
	"testing"
)

const altMessage = "From: shop@example.com\n" +
	"To: undisclosed-recipients:;\n" +
	"Subject: =?utf-8?B?T2ZlcnTEgw==?=\n" +
	"MIME-Version: 1.0\n" +
	"Content-Type: multipart/alternative;\n boundary=\"b1\"\n" +
	"\n" +
	"--b1\n" +
	"Content-Type: text/plain; charset=utf-8\n" +
	"Content-Transfer-Encoding: quoted-printable\n" +
	"\n" +
	"plain words =C8=99i more\n" +
	"--b1\n" +
	"Content-Type: text/html; charset=utf-8\n" +
	"\n" +
	"<html><body><p>html words and a longer body</p></body></html>\n" +
	"--b1--\n"

func TestTextPartMessagesSplitsAlternative(t *testing.T) {
	got := textPartMessages([]byte(altMessage))
	if len(got) != 2 {
		t.Fatalf("got %d messages", len(got))
	}
	// The larger part comes first.
	html, plain := string(got[0]), string(got[1])
	if !strings.Contains(html, "<p>html words") || strings.Contains(html, "plain words") {
		t.Fatalf("first message:\n%s", html)
	}
	if !strings.Contains(plain, "plain words =C8=99i more") || strings.Contains(plain, "html words") {
		t.Fatalf("second message:\n%s", plain)
	}
	for _, m := range got {
		msg, err := mail.ReadMessage(bytes.NewReader(m))
		if err != nil {
			t.Fatalf("not a message: %v\n%s", err, m)
		}
		if msg.Header.Get("Subject") != "=?utf-8?B?T2ZlcnTEgw==?=" || msg.Header.Get("From") != "shop@example.com" || msg.Header.Get("MIME-Version") != "1.0" {
			t.Fatalf("original headers not kept:\n%s", m)
		}
		if ct := msg.Header.Get("Content-Type"); strings.Contains(ct, "multipart") || strings.Contains(ct, "boundary") {
			t.Fatalf("content type %q", ct)
		}
		if strings.Contains(string(m), "--b1") {
			t.Fatalf("boundary left in:\n%s", m)
		}
	}
	plainMsg, _ := mail.ReadMessage(bytes.NewReader(got[1]))
	if plainMsg.Header.Get("Content-Transfer-Encoding") != "quoted-printable" || plainMsg.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("part headers not carried:\n%s", got[1])
	}
}

func TestTextPartMessagesNestedSkipsAttachments(t *testing.T) {
	msg := "Subject: s\r\n" +
		"Content-Type: multipart/mixed; boundary=outer\r\n" +
		"\r\n" +
		"--outer\r\n" +
		"Content-Type: multipart/alternative; boundary=inner\r\n" +
		"\r\n" +
		"--inner\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"inner plain\r\n" +
		"--inner\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<b>inner html</b>\r\n" +
		"--inner--\r\n" +
		"--outer\r\n" +
		"Content-Type: text/plain; name=terms.txt\r\n" +
		"Content-Disposition: attachment; filename=terms.txt\r\n" +
		"\r\n" +
		"attached terms that are much longer than either body part\r\n" +
		"--outer\r\n" +
		"Content-Type: application/pdf\r\n" +
		"\r\n" +
		"%PDF-1.4\r\n" +
		"--outer--\r\n"
	got := textPartMessages([]byte(msg))
	if len(got) != 2 {
		t.Fatalf("got %d messages: %q", len(got), got)
	}
	if !strings.Contains(string(got[0]), "<b>inner html</b>") || !strings.Contains(string(got[1]), "inner plain") {
		t.Fatalf("got %q", got)
	}
	for _, m := range got {
		if !strings.Contains(string(m), "Subject: s\r\n") || strings.Contains(string(m), "terms") || strings.Contains(string(m), "PDF") {
			t.Fatalf("message %q", m)
		}
	}
}

func TestTextPartMessagesNone(t *testing.T) {
	for name, msg := range map[string]string{
		"single part":     "Subject: s\n\nbody\n",
		"no boundary":     "Content-Type: multipart/alternative\n\n--x\n\nbody\n--x--\n",
		"no header break": "Subject: s",
		"too deep":        nested(maxPartDepth + 1),
	} {
		if got := textPartMessages([]byte(msg)); got != nil {
			t.Errorf("%s: got %q", name, got)
		}
	}
	if got := textPartMessages([]byte(nested(maxPartDepth))); len(got) != 1 {
		t.Errorf("deepest allowed nesting: got %d messages", len(got))
	}
}

// nested wraps one text part in depth multipart levels.
func nested(depth int) string {
	var b strings.Builder
	b.WriteString("Subject: s\n")
	for i := range depth {
		b.WriteString("Content-Type: multipart/mixed; boundary=b" + string(rune('a'+i)) + "\n\n--b" + string(rune('a'+i)) + "\n")
	}
	b.WriteString("Content-Type: text/plain\n\ndeep text\n")
	for i := depth - 1; i >= 0; i-- {
		b.WriteString("--b" + string(rune('a'+i)) + "--\n")
	}
	return b.String()
}

func FuzzTextPartMessages(f *testing.F) {
	f.Add([]byte(altMessage))
	f.Add([]byte(nested(3)))
	f.Add([]byte("Content-Type: multipart/mixed; boundary=x\n\n--x\nContent-Type: text/plain\n\n"))
	f.Fuzz(func(t *testing.T, msg []byte) {
		for _, m := range textPartMessages(msg) {
			parsed, err := mail.ReadMessage(bytes.NewReader(m))
			if err != nil {
				t.Fatalf("derived message does not parse: %v", err)
			}
			if strings.HasPrefix(strings.ToLower(parsed.Header.Get("Content-Type")), "multipart/") {
				t.Fatal("derived message is multipart")
			}
			// Only the rebuilt MIME lines can grow; nothing is copied twice.
			if len(m) > len(msg)+64 {
				t.Fatal("derived message is larger than its source")
			}
		}
	})
}
