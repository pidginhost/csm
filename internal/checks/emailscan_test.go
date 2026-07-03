package checks

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// base64Wrap standard-base64-encodes s and wraps it at 76 columns, mirroring
// how a MIME base64 body part is laid out in an Exim spool file.
func base64Wrap(s string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(s))
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteByte('\n')
		enc = enc[76:]
	}
	b.WriteString(enc)
	return b.String()
}

// mockEximSpool wires osFS so scanEximMessage reads fixed -H / -D spool
// contents for msgID out of the canonical /var/spool/exim/input directory.
func mockEximSpool(t *testing.T, msgID, header, body string) {
	t.Helper()
	dir := "/var/spool/exim/input"
	headerPath := filepath.Join(dir, msgID+"-H")
	bodyPath := filepath.Join(dir, msgID+"-D")

	// A real file to hand back a valid os.FileInfo from Stat.
	real := filepath.Join(t.TempDir(), "info")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		stat: func(name string) (os.FileInfo, error) {
			if name == headerPath {
				return info, nil
			}
			return nil, os.ErrNotExist
		},
		readFile: func(name string) ([]byte, error) {
			switch name {
			case headerPath:
				return []byte(header), nil
			case bodyPath:
				return []byte(body), nil
			}
			return nil, os.ErrNotExist
		},
	})
}

// eximHeader assembles a minimal valid Exim -H spool file: the msgID line, the
// envelope-user line, a recipient block, the blank separator, then the RFC 5322
// header lines (each prefixed with Exim's "NNNF " count+flag framing).
func eximHeader(msgID string, headerLines ...string) string {
	var b strings.Builder
	b.WriteString(msgID + "-H\n")
	b.WriteString("sender 100 100\n")
	b.WriteString("<sender@example.com>\n")
	b.WriteString("1\n")
	b.WriteString("rcpt@example.com\n")
	b.WriteString("\n")
	for _, h := range headerLines {
		b.WriteString("010  " + h + "\n")
	}
	return b.String()
}

// --- CHK-M01: single weak indicator must not fire High ---

func TestScanEximMessage_LoneReplyToMismatch_NotHigh(t *testing.T) {
	msgID := "1aBcDe-000001-11"
	header := eximHeader(msgID,
		"From: shop@example.com",
		"Reply-To: noreply@other.example.net",
	)
	mockEximSpool(t, msgID, header, "plain benign body text\n")

	got := scanEximMessage(msgID, "shop@example.com", &config.Config{})
	if got != nil {
		t.Fatalf("lone Reply-To mismatch must not produce a finding, got %+v (sev=%v details=%q)", got, got.Severity, got.Details)
	}
}

func TestScanEximMessage_PHPMailerNotAnIndicator(t *testing.T) {
	msgID := "1aBcDe-000002-22"
	// PHPMailer is the default WordPress transport; its X-Mailer must not be
	// treated as suspicious. "phpmail" as a substring must not catch it either.
	header := eximHeader(msgID,
		"From: shop@example.com",
		"X-Mailer: PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)",
	)
	mockEximSpool(t, msgID, header, "order confirmation body\n")

	got := scanEximMessage(msgID, "shop@example.com", &config.Config{})
	if got != nil {
		t.Fatalf("PHPMailer X-Mailer must not produce a finding, got sev=%v details=%q", got.Severity, got.Details)
	}
}

func TestScanEximMessage_TwoIndicators_High(t *testing.T) {
	msgID := "1aBcDe-000003-33"
	header := eximHeader(msgID,
		"From: shop@example.com",
		"Reply-To: collect@other.example.net",
	)
	// Two independent signals and no third: Reply-To mismatch + phishing URL.
	mockEximSpool(t, msgID, header, "click https://bit.ly/x to continue\n")

	got := scanEximMessage(msgID, "shop@example.com", &config.Config{})
	if got == nil {
		t.Fatal("two independent indicators must produce a finding")
	}
	if got.Severity != alert.High {
		t.Fatalf("two indicators severity = %v, want High; details=%q", got.Severity, got.Details)
	}
}

func TestScanEximMessage_ThreeIndicators_Critical(t *testing.T) {
	msgID := "1aBcDe-000004-44"
	header := eximHeader(msgID,
		"From: paypal-support@example.com",
		"Reply-To: collect@other.example.net",
	)
	// Reply-To mismatch + brand spoof (paypal) + phishing URL = 3 indicators.
	mockEximSpool(t, msgID, header, "verify at https://bit.ly/x now\n")

	got := scanEximMessage(msgID, "shop@example.com", &config.Config{})
	if got == nil {
		t.Fatal("three indicators must produce a finding")
	}
	if got.Severity != alert.Critical {
		t.Fatalf("three indicators severity = %v, want Critical; details=%q", got.Severity, got.Details)
	}
}

// --- CHK-M02: base64 body must be decoded, not flagged for being base64 ---

func TestScanEximMessage_Base64BodyBenign_NoFinding(t *testing.T) {
	msgID := "1aBcDe-000005-55"
	header := eximHeader(msgID,
		"From: shop@example.com",
		"Content-Type: text/html; charset=UTF-8",
		"Content-Transfer-Encoding: base64",
	)
	// base64 of "<html>hello world, your order shipped</html>" -- benign.
	body := msgID + "-D\n" +
		"PGh0bWw+aGVsbG8gd29ybGQsIHlvdXIgb3JkZXIgc2hpcHBlZDwvaHRtbD4=\n"
	mockEximSpool(t, msgID, header, body)

	got := scanEximMessage(msgID, "shop@example.com", &config.Config{})
	if got != nil {
		t.Fatalf("base64-encoded benign HTML must not produce a finding, got sev=%v details=%q", got.Severity, got.Details)
	}
}

func TestScanEximMessage_Base64BodyDecodedPhishing_Detected(t *testing.T) {
	msgID := "1aBcDe-000006-66"
	header := eximHeader(msgID,
		"From: shop@example.com",
		"Content-Type: text/html; charset=UTF-8",
		"Content-Transfer-Encoding: base64",
	)
	// Decoded payload:
	// <html>please verify your account and confirm your identity at
	//  https://evil.workers.dev/login</html>
	// -> phishing URL pattern (.workers.dev) + credential harvesting language
	//    (two phrases) = two independent indicators.
	decoded := "<html>please verify your account and confirm your identity at https://evil.workers.dev/login</html>"
	body := msgID + "-D\n" + base64Wrap(decoded) + "\n"
	mockEximSpool(t, msgID, header, body)

	got := scanEximMessage(msgID, "shop@example.com", &config.Config{})
	if got == nil {
		t.Fatal("decoded base64 phishing content must produce a finding")
	}
	if !strings.Contains(got.Details, "workers.dev") {
		t.Errorf("decoded phishing URL indicator missing; details=%q", got.Details)
	}
	if !strings.Contains(strings.ToLower(got.Details), "credential harvesting") {
		t.Errorf("decoded harvesting-language indicator missing; details=%q", got.Details)
	}
	if strings.Contains(strings.ToLower(got.Details), "base64-encoded html body") {
		t.Errorf("base64 encoding itself must not be reported as an indicator; details=%q", got.Details)
	}
}

func TestScanEximMessage_Base64MultipartLaterHTMLPayloadDetected(t *testing.T) {
	msgID := "1aBcDe-000007-77"
	header := eximHeader(msgID,
		"From: shop@example.com",
		`Content-Type: multipart/related; boundary="b1"`,
	)
	benignImage := strings.Repeat("fake image payload without phishing text ", 40)
	decoded := "<html>please verify your account and confirm your identity at https://evil.workers.dev/login</html>"
	body := msgID + "-D\n" +
		"--b1\n" +
		"Content-Type: image/png\n" +
		"Content-Transfer-Encoding: base64\n\n" +
		base64Wrap(benignImage) + "\n" +
		"--b1\n" +
		"Content-Type: text/html; charset=UTF-8\n" +
		"Content-Transfer-Encoding: base64\n\n" +
		base64Wrap(decoded) + "\n" +
		"--b1--\n"
	mockEximSpool(t, msgID, header, body)

	got := scanEximMessage(msgID, "shop@example.com", &config.Config{})
	if got == nil {
		t.Fatal("base64 phishing HTML after a longer benign MIME part must produce a finding")
	}
	if got.Severity != alert.High {
		t.Fatalf("severity = %v, want High for two decoded indicators; details=%q", got.Severity, got.Details)
	}
	if !strings.Contains(got.Details, "workers.dev") {
		t.Errorf("decoded phishing URL indicator missing; details=%q", got.Details)
	}
	if !strings.Contains(strings.ToLower(got.Details), "credential harvesting") {
		t.Errorf("decoded harvesting-language indicator missing; details=%q", got.Details)
	}
}
