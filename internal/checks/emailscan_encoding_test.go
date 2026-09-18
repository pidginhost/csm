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
