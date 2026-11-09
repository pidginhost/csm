package daemon

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// path2bTestHost makes exampleuser and acct hosting accounts and example.com
// the host's only mail domain for the length of the test.
func path2bTestHost(t testing.TB) {
	t.Helper()
	t.Cleanup(checks.SetHostingAccountLookupForTest(func(name string) string {
		switch name {
		case "exampleuser", "acct":
			return name
		}
		return ""
	}))
	withPath2bLocalDomains(t)
}

// withPath2bLocalDomains makes example.com the host's only mail domain.
func withPath2bLocalDomains(t testing.TB) {
	t.Helper()
	old := phpRelayIsLocalDomain
	phpRelayIsLocalDomain = func(domain string) (local, known bool) { return domain == "example.com", true }
	t.Cleanup(func() { phpRelayIsLocalDomain = old })
}

// phpSendLine is the arrival Exim writes when user's PHP calls mail().
func phpSendLine(at time.Time, n int, user, rcpts string) string {
	return fmt.Sprintf(`%s 1vAb%02d-000AbC-1x <= info@example.com U=%s P=local S=1200 T="Invoice %d" for %s`,
		at.Format("2006-01-02 15:04:05"), n%100, user, n, rcpts)
}

func path2bEvaluator(limit int) *evaluator {
	eng := newEvaluator(nil, nil, newPerAccountWindow(5000), defaultPHPRelayCfg(), nil)
	eng.SetEffectiveAccountLimit(limit)
	return eng
}

func volumeAccountFindings(eng *evaluator, lines []string, now time.Time) []alert.Finding {
	var out []alert.Finding
	for _, line := range lines {
		for _, f := range eng.parsePHPRelayAccountVolume(line, now) {
			if f.Path == "volume_account" {
				out = append(out, f)
			}
		}
	}
	return out
}

func TestPath2bCountsOutboundPHPMail(t *testing.T) {
	path2bTestHost(t)
	now := time.Now()
	eng := path2bEvaluator(3)
	var lines []string
	for i := range 3 {
		lines = append(lines, phpSendLine(now, i, "exampleuser", "buyer@example.net"))
	}
	got := volumeAccountFindings(eng, lines, now)
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want one", got)
	}
	if got[0].CPUser != "exampleuser" || got[0].TenantID != "exampleuser" || got[0].RelayTotal != 3 {
		t.Fatalf("finding = %+v", got[0])
	}
}

func TestPath2bCountsMixedRecipientsOnce(t *testing.T) {
	path2bTestHost(t)
	now := time.Now()
	eng := path2bEvaluator(3)
	var lines []string
	for i := range 3 {
		lines = append(lines, phpSendLine(now, i, "exampleuser", "office@example.com buyer@example.net"))
	}
	got := volumeAccountFindings(eng, lines, now)
	if len(got) != 1 || got[0].RelayTotal != 3 {
		t.Fatalf("findings = %+v, want one with three messages", got)
	}
}

// Mail an account's scripts deliver to the host's own mailboxes, such as
// contact forms and cron output, is not outbound volume.
func TestPath2bIgnoresLocalOnlyMail(t *testing.T) {
	path2bTestHost(t)
	now := time.Now()
	eng := path2bEvaluator(1)
	if got := volumeAccountFindings(eng, []string{phpSendLine(now, 1, "exampleuser", "office@Example.COM")}, now); len(got) != 0 {
		t.Fatalf("local delivery fed the outbound volume alert: %+v", got)
	}
}

// Only Exim's own submission metadata names the sending account. A remote
// sender controls the subject, envelope and message ID, and none of them may
// count a send against a hosted account.
func TestPath2bIgnoresForgedAccountText(t *testing.T) {
	path2bTestHost(t)
	now := time.Now()
	eng := path2bEvaluator(1)
	stamp := now.Format("2006-01-02 15:04:05")
	forged := []string{
		stamp + ` 1vAbCd-000AbC-1x <= x@example.org H=mx.example.org [203.0.113.9]:40000 P=esmtps S=900 T="x <= y U=exampleuser P=local B=redirect_resolver" for buyer@example.net`,
		stamp + ` 1vAbCd-000AbC-1y <= "U=exampleuser P=local"@example.org H=mx.example.org [203.0.113.9]:40000 P=esmtps S=900 for buyer@example.net`,
		stamp + ` 1vAbCd-000AbC-1z <= x@example.org H=mx.example.org [203.0.113.9]:40000 P=esmtps S=900 id="U=exampleuser P=local"@example.org for buyer@example.net`,
	}
	if got := volumeAccountFindings(eng, forged, now); len(got) != 0 {
		t.Fatalf("forged text fed the outbound volume alert: %+v", got)
	}
}

func TestPath2bIgnoresNonAccountAndNonPHPSenders(t *testing.T) {
	path2bTestHost(t)
	now := time.Now()
	eng := path2bEvaluator(1)
	stamp := now.Format("2006-01-02 15:04:05")
	lines := []string{
		phpSendLine(now, 1, "root", "buyer@example.net"),
		phpSendLine(now, 2, "mailnull", "buyer@example.net"),
		stamp + ` 1vAbCd-000AbC-2a <= <> R=1vAbCd-000AbC-1x U=exampleuser P=local S=800 T="Out of office" for buyer@example.net`,
		stamp + ` 1vAbCd-000AbC-2b <= info@example.com H=(client) [203.0.113.7]:51000 P=esmtpsa X=TLS1.3 A=dovecot_login:info@example.com S=1200 for buyer@example.net`,
		stamp + ` 1vAbCd-000AbC-2c <= info@example.com U=exampleuser P=local S=1200 T="No recipients logged"`,
	}
	if got := volumeAccountFindings(eng, lines, now); len(got) != 0 {
		t.Fatalf("non-PHP or non-account mail fed the outbound volume alert: %+v", got)
	}
}

// Without the host's mail domains every delivery would look outbound, so
// the alert stays quiet rather than counting cron and form mail.
func TestPath2bSkipsWhenLocalDomainsUnknown(t *testing.T) {
	path2bTestHost(t)
	phpRelayIsLocalDomain = func(string) (bool, bool) { return false, false }
	now := time.Now()
	eng := path2bEvaluator(1)
	if got := volumeAccountFindings(eng, []string{phpSendLine(now, 1, "exampleuser", "buyer@example.net")}, now); len(got) != 0 {
		t.Fatalf("unknown local domains still counted a send: %+v", got)
	}
}

func TestPhpSendLineIsARealArrival(t *testing.T) {
	line := phpSendLine(time.Now(), 7, "exampleuser", "buyer@example.net")
	if !strings.Contains(line, " P=local ") || !strings.Contains(line, " for buyer@example.net") {
		t.Fatalf("fixture lost its shape: %s", line)
	}
}
