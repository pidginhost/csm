package daemon

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/eximlog"
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

func TestPath2bMessageDataCannotChangeOutboundVolume(t *testing.T) {
	path2bTestHost(t)
	now := time.Now()
	const prefix = "2026-01-01 10:00:00 1abc23-000456-AB <= "
	for _, tc := range []struct {
		name, record string
		want         int
	}{
		{"apostrophe in message id", `info@example.com U=exampleuser P=local S=100 id='notice@example.org for buyer@example.net`, 1},
		{"message id cannot forge recipients", `info@example.com U=exampleuser P=local S=100 id='tag."a' for forged@example.net "@example.org for office@example.com`, 0},
		{"escaped quote in sender", `notice\"tag@example.com U=exampleuser P=local S=100 for buyer@example.net`, 1},
		{"escaped quote in message id", `info@example.com U=exampleuser P=local S=100 id=notice\"tag@example.org for buyer@example.net`, 1},
		{"escaped quote in recipient", `info@example.com U=exampleuser P=local S=100 for notice\"tag@example.net`, 1},
		{"escaped space in local recipient", `info@example.com U=exampleuser P=local S=100 for notice\ @example.net\ tag@example.com`, 0},
		{"truncated local recipient", `info@example.com U=exampleuser P=local S=100 for office@example.com office@exam<trunc>`, 0},
		{"outbound before truncation", `info@example.com U=exampleuser P=local S=100 for buyer@example.net office@exam<trunc>`, 1},
		{"truncation text in quoted recipient", `info@example.com U=exampleuser P=local S=100 for "<trunc>"@example.net`, 1},
		{"subject cannot invent absent recipients", `info@example.com U=exampleuser P=local S=100 T="for buyer@example.net"`, 0},
		{"message id cannot invent absent recipients", `info@example.com U=exampleuser P=local S=100 id="for buyer@example.net"@example.org`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := path2bEvaluator(1)
			got := eng.parsePHPRelayAccountVolume(prefix+tc.record, now)
			if len(got) != tc.want {
				t.Fatalf("findings = %+v, want %d", got, tc.want)
			}
			if volume := eng.accounts.volumeSince("exampleuser", now.Add(-time.Hour)); volume != tc.want {
				t.Fatalf("account volume = %d, want %d", volume, tc.want)
			}
		})
	}
}

func TestPhpSendLineIsARealArrival(t *testing.T) {
	line := phpSendLine(time.Now(), 7, "exampleuser", "buyer@example.net")
	if id, sender, ok := eximlog.Arrival(line); !ok || id != "1vAb07-000AbC-1x" || sender != "info@example.com" {
		t.Fatalf("fixture arrival = %q, %q, %v", id, sender, ok)
	}
	if user := eximlog.LocalSubmitter(line); user != "exampleuser" {
		t.Fatalf("fixture submitter = %q", user)
	}
	if recipients := eximlog.Recipients(line); !reflect.DeepEqual(recipients, []string{"buyer@example.net"}) {
		t.Fatalf("fixture recipients = %q", recipients)
	}
}

func TestPath2bRetainsOnlyHostingAccountKeys(t *testing.T) {
	path2bTestHost(t)
	now := time.Now()
	eng := path2bEvaluator(2)
	for i := range 256 {
		user := fmt.Sprintf("unknown%d", i)
		if got := eng.parsePHPRelayAccountVolume(phpSendLine(now, i, user, "buyer@example.net"), now); len(got) != 0 {
			t.Fatalf("unknown user produced findings: %+v", got)
		}
	}
	eng.parsePHPRelayAccountVolume(phpSendLine(now, 1, "exampleuser", "buyer@example.net"), now)
	var keys []string
	eng.accounts.states.Range(func(key, _ any) bool {
		keys = append(keys, key.(string))
		return true
	})
	if !reflect.DeepEqual(keys, []string{"exampleuser"}) {
		t.Fatalf("retained account keys = %q, want only exampleuser", keys)
	}
}
