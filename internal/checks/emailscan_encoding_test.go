package checks

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

const encodedPhishHTML = "<html>please verify your account and confirm your identity at https://evil.workers.dev/login</html>"

// spacedBase64 inserts a space inside every wrapped line. Mail clients ignore
// bytes outside the base64 alphabet (RFC 2045 section 6.8), so the recipient
// still sees the decoded page.
func spacedBase64(s string) string {
	lines := strings.Split(base64Wrap(s), "\n")
	for i, l := range lines {
		if len(l) > 8 {
			lines[i] = l[:8] + " " + l[8:]
		}
	}
	return strings.Join(lines, "\n")
}

func requireDecodedPhishing(t *testing.T, msgID, header, body string) {
	t.Helper()
	mockEximSpool(t, msgID, header, body)
	got := scanEximMessage(msgID, "shop@example.com", &config.Config{})
	if got == nil {
		t.Fatal("phishing content behind malformed base64 must still be decoded and reported")
	}
	if !strings.Contains(got.Details, "workers.dev") {
		t.Errorf("decoded phishing URL indicator missing; details=%q", got.Details)
	}
	if !strings.Contains(strings.ToLower(got.Details), "credential harvesting") {
		t.Errorf("decoded harvesting-language indicator missing; details=%q", got.Details)
	}
}

func TestScanEximMessage_Base64BodyWithInnerSpacesDetected(t *testing.T) {
	msgID := "1aBcDe-000011-11"
	header := eximHeader(msgID,
		"From: shop@example.com",
		"Content-Type: text/html; charset=UTF-8",
		"Content-Transfer-Encoding: base64",
	)
	requireDecodedPhishing(t, msgID, header, msgID+"-D\n"+spacedBase64(encodedPhishHTML)+"\n")
}

func TestScanEximMessage_Base64MultipartPartWithInnerSpacesDetected(t *testing.T) {
	msgID := "1aBcDe-000012-22"
	header := eximHeader(msgID,
		"From: shop@example.com",
		`Content-Type: multipart/alternative; boundary="b2"`,
	)
	body := msgID + "-D\n" +
		"--b2\n" +
		"Content-Type: text/html; charset=UTF-8\n" +
		"Content-Transfer-Encoding: base64\n\n" +
		spacedBase64(encodedPhishHTML) + "\n" +
		"--b2--\n"
	requireDecodedPhishing(t, msgID, header, body)
}

// Header whitespace after the colon is optional (RFC 5322), and the
// encoding name is case-insensitive.
func TestScanEximMessage_Base64HeaderSpacingVariantsDetected(t *testing.T) {
	for i, cte := range []string{"Content-Transfer-Encoding:base64", "Content-Transfer-Encoding:\tBASE64", "content-transfer-encoding:   Base64"} {
		msgID := "1aBcDe-00002" + string(rune('0'+i)) + "-33"
		header := eximHeader(msgID,
			"From: shop@example.com",
			`Content-Type: multipart/alternative; boundary="b3"`,
		)
		body := msgID + "-D\n" +
			"--b3\n" +
			"Content-Type: text/html; charset=UTF-8\n" +
			cte + "\n\n" +
			base64Wrap(encodedPhishHTML) + "\n" +
			"--b3--\n"
		t.Run(cte, func(t *testing.T) { requireDecodedPhishing(t, msgID, header, body) })
	}
}

func TestScanEximMessage_Base64MIMEFraming(t *testing.T) {
	msgID := "1aBcDe-000031-11"
	payload := base64Wrap(encodedPhishHTML)
	cases := []struct{ name, contentType, cte, body string }{
		{"plain text", "text/plain", "base64", payload},
		{"folded boundary", "multipart/alternative;\n\tboundary=\"CaseSensitive\"", "", "--CaseSensitive\nContent-Type: text/html\nContent-Transfer-Encoding: base64\n\n" + payload + "\n--CaseSensitive--\n"},
		{"clipped final part", `multipart/mixed; boundary="CaseSensitive"`, "", "--CaseSensitive\nContent-Type: text/html\nContent-Transfer-Encoding: base64\n\n" + payload + "QUJ"},
		{"nested multipart", `multipart/mixed; boundary="outer"`, "", "--outer\nContent-Type: multipart/alternative; boundary=inner\n\n--inner\nContent-Type: text/html\nContent-Transfer-Encoding: base64\n\n" + payload + "\n--inner--\n--outer--\n"},
		{"encoding comment", "text/html", "base64 (MIME encoding)", payload},
		{"multipart comment", `multipart/mixed (MIME body); boundary="Case(Sensitive)"`, "", "--Case(Sensitive)\nContent-Type: text/html\nContent-Transfer-Encoding: base64\n\n" + payload + "\n--Case(Sensitive)--\n"},
		{"encapsulated message", "message/rfc822", "", "Content-Type: text/html\nContent-Transfer-Encoding: base64\n\n" + payload},
		{"single stray dashes", "text/html", "base64", "--\n" + payload},
		{"folded top encoding", "text/html", "\n\tbase64", payload},
		{"folded part encoding", `multipart/alternative; boundary="CaseSensitive"`, "", "--CaseSensitive\nContent-Type: text/html\nContent-Transfer-Encoding:\n\tbase64\n\n" + payload + "\n--CaseSensitive--\n"},
		{"part stray dashes", `multipart/alternative; boundary="CaseSensitive"`, "", "--CaseSensitive\nContent-Type: text/html\nContent-Transfer-Encoding: base64\n\n--\n" + payload + "\n--CaseSensitive--\n"},
		{"malformed preceding part", `multipart/mixed; boundary="CaseSensitive"`, "", "--CaseSensitive\nContent-Transfer-Encoding: base64\ninvalid header\n--CaseSensitive\nContent-Type: text/html\nContent-Transfer-Encoding: base64\n\n" + payload + "\n--CaseSensitive--\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := eximHeader(msgID, "From: shop@example.com", "Content-Type: "+tc.contentType)
			if tc.cte != "" {
				header += "010  Content-Transfer-Encoding: " + tc.cte + "\n"
			}
			requireDecodedPhishing(t, msgID, header, msgID+"-D\n"+tc.body)
		})
	}
}

func TestScanEximMessage_Base64HeaderTextIsNotFraming(t *testing.T) {
	msgID := "1aBcDe-000032-11"
	// One phrase lives in each part. Treating an extension header as a CTE
	// decodes the other phrase and manufactures the second alert indicator.
	first := "verify your account at https://evil.workers.dev/login"
	second := base64Wrap("confirm your identity")
	for _, fake := range []string{"X-Content-Transfer-Encoding: base64", "X-Note: content-transfer-encoding: base64"} {
		t.Run(fake, func(t *testing.T) {
			header := eximHeader(msgID, "From: shop@example.com", `Content-Type: multipart/mixed; boundary="b"`)
			body := msgID + "-D\n--b\nContent-Type: text/html\nContent-Transfer-Encoding: base64\n\n" + base64Wrap(first) + "\n--b\nContent-Type: text/plain\n" + fake + "\n\n" + second + "\n--b--\n"
			mockEximSpool(t, msgID, header, body)
			if got := scanEximMessage(msgID, "shop@example.com", &config.Config{}); got != nil {
				t.Fatalf("header text manufactured phishing indicators: %s", got.Details)
			}
		})
	}
}

func TestScanEximMessage_Base64DuplicateEncodingUsesFirstHeader(t *testing.T) {
	msgID := "1aBcDe-000033-11"
	header := eximHeader(msgID, "From: shop@example.com", "Content-Type: text/html",
		"Content-Transfer-Encoding: base64", "Content-Transfer-Encoding: 7bit")
	requireDecodedPhishing(t, msgID, header, msgID+"-D\n"+base64Wrap(encodedPhishHTML))
}

func TestScanEximMessage_Base64CRLFMarker(t *testing.T) {
	msgID := "1aBcDe-000034-11"
	header := eximHeader(msgID, "From: shop@example.com", "Content-Type: text/html", "Content-Transfer-Encoding: base64")
	requireDecodedPhishing(t, msgID, header, msgID+"-D\r\n"+base64Wrap(encodedPhishHTML))
}

func TestScanEximMessage_Base64DeletedHeadersIgnored(t *testing.T) {
	msgID := "1aBcDe-000035-11"
	header := eximHeader(msgID, "From: shop@example.com", "Content-Type: text/html") +
		"040* Content-Transfer-Encoding: base64\n (deleted header)\n"
	mockEximSpool(t, msgID, header, msgID+"-D\n"+base64Wrap(encodedPhishHTML))
	if got := scanEximMessage(msgID, "shop@example.com", &config.Config{}); got != nil {
		t.Fatalf("deleted encoding header caused a false alert: %s", got.Details)
	}
}

func TestDecodeBase64BodyPreservesContentAndFraming(t *testing.T) {
	payload := "<html>verify your account</html>"
	// The decoder must ignore preamble, epilogue, a case-mismatched delimiter,
	// and CTE-looking text inside an ordinary part body.
	body := "Content-Transfer-Encoding: base64\n\n" + base64Wrap("preamble") + "\n" +
		"--Case\t \r\nContent-Transfer-Encoding: base64\r\n\r\n--" + base64Wrap(payload) + "\r\n" +
		"--Case\r\nContent-Type: text/plain\r\n\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64Wrap("not encoded") + "\r\n" +
		"--case\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64Wrap("wrong case") + "\r\n" +
		"--Case--\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64Wrap("epilogue")
	if got := decodeBase64Body([]byte(body), `multipart/mixed; boundary="Case"`, ""); got != payload {
		t.Fatalf("decoded %q, want only %q", got, payload)
	}
}
