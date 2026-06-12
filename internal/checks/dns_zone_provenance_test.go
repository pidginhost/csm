package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// cPanel stamps each zone it writes with this header. update_time advances on
// every cPanel-mediated edit; a change without it advancing is out of band.
func cpanelHeader(updateTime int64) string {
	return fmt.Sprintf("; cPanel first:11.42.0.8 (update_time):%d Cpanel::ZoneFile::VERSION:1.3 hostname:host.example.net latest:136.0.20\n", updateTime)
}

// zoneFixture builds a minimal but realistic cPanel zone. Documentation IPs
// (RFC 5737) are used throughout. apexA / nsHost / mxHost / extra let each test
// vary exactly the record under test.
func zoneFixture(updateTime int64, serial int, apexA, nsHost, mxHost, extra string) string {
	var b strings.Builder
	b.WriteString(cpanelHeader(updateTime))
	b.WriteString("$TTL 14400\n")
	fmt.Fprintf(&b, "example.com.\t86400\tIN\tSOA\tns1.example.net. admin.example.net. %d 3600 1800 1209600 86400\n", serial)
	fmt.Fprintf(&b, "example.com.\t86400\tIN\tNS\t%s\n", nsHost)
	b.WriteString("example.com.\t86400\tIN\tNS\tns2.example.net.\n")
	fmt.Fprintf(&b, "example.com.\t14400\tIN\tA\t%s\n", apexA)
	fmt.Fprintf(&b, "example.com.\t14400\tIN\tMX\t0 %s\n", mxHost)
	b.WriteString("www\t14400\tIN\tA\t192.0.2.10\n")
	if extra != "" {
		b.WriteString(extra)
		if !strings.HasSuffix(extra, "\n") {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func nonCpanelZoneFixture(serial int, apexA, nsHost, mxHost, extra string) string {
	return strings.TrimPrefix(zoneFixture(0, serial, apexA, nsHost, mxHost, extra), cpanelHeader(0))
}

// dnsZoneTestOS serves a fixed set of /var/named zone files. The map is shared
// with the test so it can mutate a zone between check runs.
func dnsZoneTestOS(files map[string]string) *mockOS {
	return &mockOS{
		readDir: func(name string) ([]os.DirEntry, error) {
			if name != "/var/named" {
				return nil, os.ErrNotExist
			}
			var entries []os.DirEntry
			for fn := range files {
				entries = append(entries, fakeDirEntry{fi: fakeFileInfo{name: fn}})
			}
			return entries, nil
		},
		readFile: func(p string) ([]byte, error) {
			if c, ok := files[filepath.Base(p)]; ok {
				return []byte(c), nil
			}
			return nil, os.ErrNotExist
		},
	}
}

func runDNSZoneCheck(t *testing.T, files map[string]string, store *state.Store) []alert.Finding {
	t.Helper()
	withMockOS(t, dnsZoneTestOS(files))
	return CheckDNSZoneChanges(context.Background(), &config.Config{}, store)
}

func newDNSTestStore(t *testing.T) *state.Store {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// Baseline: the first observation of a zone never alerts.
func TestDNSZoneBaselineNoAlert(t *testing.T) {
	files := map[string]string{
		"example.com.db": zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	st := newDNSTestStore(t)
	if f := runDNSZoneCheck(t, files, st); len(f) != 0 {
		t.Fatalf("baseline run should not alert, got %d: %+v", len(f), f)
	}
}

// A serial bump (and its update_time advance) with no record change is the most
// common cPanel write and must stay silent.
func TestDNSZoneSerialBumpSuppressed(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{
		"example.com.db": zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	runDNSZoneCheck(t, files, st) // baseline

	files["example.com.db"] = zoneFixture(1001, 2026010102, "192.0.2.1", "ns1.example.net.", "mail.example.com.", "")
	if f := runDNSZoneCheck(t, files, st); len(f) != 0 {
		t.Fatalf("serial bump should be suppressed, got %d: %+v", len(f), f)
	}
}

// A manually managed zone has no cPanel header, so provenance stays 0 forever.
// Serial-only reloads must still suppress because the security fingerprint is
// unchanged, not because provenance advanced.
func TestDNSZoneNonCpanelSerialBumpSuppressed(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{
		"example.com.db": nonCpanelZoneFixture(2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	runDNSZoneCheck(t, files, st)

	files["example.com.db"] = nonCpanelZoneFixture(2026010102, "192.0.2.1", "ns1.example.net.", "mail.example.com.", "")
	if f := runDNSZoneCheck(t, files, st); len(f) != 0 {
		t.Fatalf("non-cPanel serial bump should be suppressed, got %d: %+v", len(f), f)
	}
	if f := runDNSZoneCheck(t, files, st); len(f) != 0 {
		t.Fatalf("unchanged non-cPanel reload should stay suppressed, got %d: %+v", len(f), f)
	}
}

// A zone that did not previously carry cPanel provenance cannot become trusted
// merely because the new file contains an update_time-looking marker.
func TestDNSZoneDoesNotTrustNewProvenanceOnManualZone(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{
		"example.com.db": nonCpanelZoneFixture(2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	runDNSZoneCheck(t, files, st)

	files["example.com.db"] = zoneFixture(9999, 2026010102, "203.0.113.66", "ns1.example.net.", "mail.example.com.", "")
	f := runDNSZoneCheck(t, files, st)
	if len(f) != 1 || f[0].Severity != alert.High {
		t.Fatalf("manual zone with new provenance and apex change should be 1 High, got %+v", f)
	}
}

func TestDNSZoneManualZoneHeaderOnlyChangeDoesNotEnableTrust(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{
		"example.com.db": nonCpanelZoneFixture(2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	runDNSZoneCheck(t, files, st)

	files["example.com.db"] = zoneFixture(1000, 2026010102, "192.0.2.1", "ns1.example.net.", "mail.example.com.", "")
	if f := runDNSZoneCheck(t, files, st); len(f) != 0 {
		t.Fatalf("header-only manual-zone change should be suppressed, got %+v", f)
	}

	files["example.com.db"] = zoneFixture(1001, 2026010103, "203.0.113.66", "ns1.example.net.", "mail.example.com.", "")
	f := runDNSZoneCheck(t, files, st)
	if len(f) != 1 || f[0].Severity != alert.High {
		t.Fatalf("manual zone must stay untrusted after fake header, got %+v", f)
	}
}

// Adding a DCV/DKIM TXT record and a new subdomain A through cPanel must stay
// silent: neither is a security-relevant record.
func TestDNSZoneTXTAndSubdomainSuppressed(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{
		"example.com.db": zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	runDNSZoneCheck(t, files, st)

	extra := "_cpanel-dcv-test-record\t14400\tIN\tTXT\t\"_cpanel-dcv-test-record=abc;def\"\nshop\t14400\tIN\tA\t192.0.2.55\n"
	files["example.com.db"] = zoneFixture(1001, 2026010102, "192.0.2.1", "ns1.example.net.", "mail.example.com.", extra)
	if f := runDNSZoneCheck(t, files, st); len(f) != 0 {
		t.Fatalf("TXT/subdomain change should be suppressed, got %d: %+v", len(f), f)
	}
}

// An apex A repoint applied through cPanel (update_time advances) by the
// authenticated owner is routine and must stay silent.
func TestDNSZoneApexAViaCpanelSuppressed(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{
		"example.com.db": zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	runDNSZoneCheck(t, files, st)

	files["example.com.db"] = zoneFixture(1001, 2026010102, "192.0.2.99", "ns1.example.net.", "mail.example.com.", "")
	if f := runDNSZoneCheck(t, files, st); len(f) != 0 {
		t.Fatalf("cPanel apex A repoint should be suppressed, got %d: %+v", len(f), f)
	}
}

// An NS change applied through cPanel surfaces as a Warning: legitimate
// migrations happen, but so does a compromised account redelegating a domain.
func TestDNSZoneNSChangeViaCpanelWarning(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{
		"example.com.db": zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	runDNSZoneCheck(t, files, st)

	files["example.com.db"] = zoneFixture(1001, 2026010102, "192.0.2.1", "ns1.attacker-but-via-panel.test.", "mail.example.com.", "")
	f := runDNSZoneCheck(t, files, st)
	if len(f) != 1 {
		t.Fatalf("cPanel NS change should produce 1 finding, got %d: %+v", len(f), f)
	}
	if f[0].Severity != alert.Warning {
		t.Errorf("severity = %v, want Warning", f[0].Severity)
	}
	if f[0].Check != "dns_zone_change" {
		t.Errorf("check = %q", f[0].Check)
	}
}

// An MX change applied through cPanel also surfaces as a Warning (mail
// redirection is a takeover vector).
func TestDNSZoneMXChangeViaCpanelWarning(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{
		"example.com.db": zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	runDNSZoneCheck(t, files, st)

	files["example.com.db"] = zoneFixture(1001, 2026010102, "192.0.2.1", "ns1.example.net.", "mail.elsewhere.test.", "")
	f := runDNSZoneCheck(t, files, st)
	if len(f) != 1 || f[0].Severity != alert.Warning {
		t.Fatalf("cPanel MX change should be 1 Warning, got %+v", f)
	}
}

// An NS change with NO cPanel update_time advance means the zone file was
// edited out of band -- the hijack signature -- and must be High.
func TestDNSZoneNSChangeOutOfBandHigh(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{
		"example.com.db": zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	runDNSZoneCheck(t, files, st)

	// update_time stays at 1000: cPanel did not write this change.
	files["example.com.db"] = zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.evil.test.", "mail.example.com.", "")
	f := runDNSZoneCheck(t, files, st)
	if len(f) != 1 {
		t.Fatalf("out-of-band NS change should produce 1 finding, got %d: %+v", len(f), f)
	}
	if f[0].Severity != alert.High {
		t.Errorf("severity = %v, want High", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "outside cPanel") {
		t.Errorf("message = %q, want out-of-band wording", f[0].Message)
	}
}

// An apex A change with no provenance advance is also out of band: an attacker
// editing the zone file directly to repoint the domain. Must be High.
func TestDNSZoneApexAOutOfBandHigh(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{
		"example.com.db": zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	runDNSZoneCheck(t, files, st)

	files["example.com.db"] = zoneFixture(1000, 2026010101, "203.0.113.66", "ns1.example.net.", "mail.example.com.", "")
	f := runDNSZoneCheck(t, files, st)
	if len(f) != 1 || f[0].Severity != alert.High {
		t.Fatalf("out-of-band apex A change should be 1 High, got %+v", f)
	}
}

func TestDNSZoneStaleProvenanceDoesNotLowerBaseline(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{
		"example.com.db": zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	runDNSZoneCheck(t, files, st)

	files["example.com.db"] = zoneFixture(999, 2026010102, "203.0.113.66", "ns1.example.net.", "mail.example.com.", "")
	if f := runDNSZoneCheck(t, files, st); len(f) != 1 || f[0].Severity != alert.High {
		t.Fatalf("stale-provenance apex change should be 1 High, got %+v", f)
	}

	files["example.com.db"] = zoneFixture(1000, 2026010103, "203.0.113.77", "ns1.example.net.", "mail.example.com.", "")
	if f := runDNSZoneCheck(t, files, st); len(f) != 1 || f[0].Severity != alert.High {
		t.Fatalf("stale provenance must not lower later baseline, got %+v", f)
	}
}

// A purely cosmetic out-of-band edit (a comment line, no security record
// touched) must stay silent even though the file hash changed and update_time
// did not advance -- the fingerprint, not the raw bytes, is what matters.
func TestDNSZoneOutOfBandNonSecurityChangeSuppressed(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{
		"example.com.db": zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	runDNSZoneCheck(t, files, st)

	files["example.com.db"] = zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", "; an extra comment\nblog\t14400\tIN\tA\t192.0.2.77")
	if f := runDNSZoneCheck(t, files, st); len(f) != 0 {
		t.Fatalf("non-security out-of-band change should be suppressed, got %d: %+v", len(f), f)
	}
}

// BIND include/generate directives can materialize records outside this file's
// normal line parser. Adding one out of band must change the fingerprint.
func TestDNSZoneIncludeDirectiveOutOfBandHigh(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{
		"example.com.db": zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	runDNSZoneCheck(t, files, st)

	files["example.com.db"] = zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", "$INCLUDE /var/named/evil-records.inc\n")
	f := runDNSZoneCheck(t, files, st)
	if len(f) != 1 || f[0].Severity != alert.High {
		t.Fatalf("out-of-band include directive should be 1 High, got %+v", f)
	}
}

// Legacy state written by an earlier version is a bare 64-char hex hash. On
// upgrade the check must re-baseline silently rather than alert on every zone.
func TestDNSZoneLegacyStateMigration(t *testing.T) {
	st := newDNSTestStore(t)
	st.SetRaw("_dns_zone:example.com.db", hashBytes([]byte("old whole-file content")))

	files := map[string]string{
		"example.com.db": zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	if f := runDNSZoneCheck(t, files, st); len(f) != 0 {
		t.Fatalf("legacy-state upgrade should re-baseline silently, got %d: %+v", len(f), f)
	}
	// State must now be rewritten in the new JSON form.
	raw, ok := st.GetRaw("_dns_zone:example.com.db")
	if !ok || !strings.HasPrefix(raw, "{") {
		t.Fatalf("state not migrated to JSON form: ok=%v raw=%q", ok, raw)
	}
}

// Corrupt JSON-shaped state should be repaired once. It must not create a
// permanent re-baseline path that suppresses the next real security change.
func TestDNSZoneCorruptJSONStateRepaired(t *testing.T) {
	st := newDNSTestStore(t)
	st.SetRaw("_dns_zone:example.com.db", "{not-json")

	files := map[string]string{
		"example.com.db": zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", ""),
	}
	if f := runDNSZoneCheck(t, files, st); len(f) != 0 {
		t.Fatalf("corrupt-state repair should re-baseline silently, got %d: %+v", len(f), f)
	}
	raw, ok := st.GetRaw("_dns_zone:example.com.db")
	if !ok {
		t.Fatal("state missing after corrupt-state repair")
	}
	if _, decoded := decodeDNSZoneState(raw); !decoded {
		t.Fatalf("state was not repaired to decodable JSON: %q", raw)
	}

	files["example.com.db"] = zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.evil.test.", "mail.example.com.", "")
	f := runDNSZoneCheck(t, files, st)
	if len(f) != 1 || f[0].Severity != alert.High {
		t.Fatalf("security change after repair should be 1 High, got %+v", f)
	}
}

// Mass benign change (every zone gets a serial bump via cPanel) stays silent:
// the per-record model handles it, no bulk gate needed.
func TestDNSZoneMassBenignChangeSuppressed(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{}
	for i := 0; i < 8; i++ {
		files[fmt.Sprintf("zone%d.db", i)] = zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", "")
	}
	runDNSZoneCheck(t, files, st)

	for i := 0; i < 8; i++ {
		files[fmt.Sprintf("zone%d.db", i)] = zoneFixture(1001, 2026010102, "192.0.2.1", "ns1.example.net.", "mail.example.com.", "")
	}
	if f := runDNSZoneCheck(t, files, st); len(f) != 0 {
		t.Fatalf("mass serial bump should be suppressed, got %d: %+v", len(f), f)
	}
}

// Mass OUT-OF-BAND NS rewrite across many zones at once is the worst-case
// hijack and must NOT be suppressed: every zone reports High. This is the hole
// the old >5-zone bulk gate left open.
func TestDNSZoneMassOutOfBandNSChangeAllHigh(t *testing.T) {
	st := newDNSTestStore(t)
	files := map[string]string{}
	for i := 0; i < 8; i++ {
		files[fmt.Sprintf("zone%d.db", i)] = zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.example.net.", "mail.example.com.", "")
	}
	runDNSZoneCheck(t, files, st)

	for i := 0; i < 8; i++ {
		// No update_time advance: out of band on every zone.
		files[fmt.Sprintf("zone%d.db", i)] = zoneFixture(1000, 2026010101, "192.0.2.1", "ns1.evil.test.", "mail.example.com.", "")
	}
	f := runDNSZoneCheck(t, files, st)
	if len(f) != 8 {
		t.Fatalf("mass out-of-band NS change should report all 8 zones, got %d", len(f))
	}
	for _, finding := range f {
		if finding.Severity != alert.High {
			t.Fatalf("every mass out-of-band finding must be High, got %v", finding.Severity)
		}
	}
}

// Reordering records and reformatting whitespace, with no semantic change and
// no provenance advance, must stay silent (canonicalization).
func TestDNSZoneReorderNoAlert(t *testing.T) {
	st := newDNSTestStore(t)
	base := cpanelHeader(1000) +
		"$TTL 14400\n" +
		"example.com.\t86400\tIN\tNS\tns1.example.net.\n" +
		"example.com.\t86400\tIN\tNS\tns2.example.net.\n" +
		"example.com.\t14400\tIN\tA\t192.0.2.1\n"
	reordered := cpanelHeader(1000) +
		"$TTL 14400\n" +
		"example.com.   14400   IN   A   192.0.2.1\n" +
		"example.com.   86400   IN   NS   ns2.example.net.\n" +
		"example.com.   86400   IN   NS   ns1.example.net.\n"

	files := map[string]string{"example.com.db": base}
	runDNSZoneCheck(t, files, st)
	files["example.com.db"] = reordered
	if f := runDNSZoneCheck(t, files, st); len(f) != 0 {
		t.Fatalf("reorder/whitespace change should be suppressed, got %d: %+v", len(f), f)
	}
}

func TestZoneUpdateTimeOnlyAcceptsLeadingCpanelHeader(t *testing.T) {
	if got := zoneUpdateTime([]byte(cpanelHeader(1234))); got != 1234 {
		t.Fatalf("cPanel header update_time = %d, want 1234", got)
	}

	fakeLeadingComment := []byte("; not a cPanel header (update_time):9999\n")
	if got := zoneUpdateTime(fakeLeadingComment); got != 0 {
		t.Fatalf("fake leading comment update_time = %d, want 0", got)
	}

	recordMarker := []byte("$TTL 14400\nexample.com. IN TXT \"(update_time):9999\"\n")
	if got := zoneUpdateTime(recordMarker); got != 0 {
		t.Fatalf("record marker update_time = %d, want 0", got)
	}

	lateComment := []byte("$TTL 14400\n; cPanel first:1 (update_time):9999 Cpanel::ZoneFile::VERSION:1.3\n")
	if got := zoneUpdateTime(lateComment); got != 0 {
		t.Fatalf("late comment update_time = %d, want 0", got)
	}

	overflow := []byte("; cPanel first:1 (update_time):99999999999999999999999999 Cpanel::ZoneFile::VERSION:1.3\n")
	if got := zoneUpdateTime(overflow); got != 0 {
		t.Fatalf("overflow update_time = %d, want 0", got)
	}
}

func TestParseZoneSecurityInlineSOAParenDoesNotHideRecords(t *testing.T) {
	base := "example.com. IN SOA ns1.example.net. admin.example.net. ( 2026010101 3600 1800 1209600 86400 )\n" +
		"example.com. IN NS ns1.example.net.\n"
	changed := "example.com. IN SOA ns1.example.net. admin.example.net. ( 2026010101 3600 1800 1209600 86400 )\n" +
		"example.com. IN NS ns2.example.net.\n"

	_, baseDeleg := parseZoneSecurity([]byte(base), "example.com.")
	_, changedDeleg := parseZoneSecurity([]byte(changed), "example.com.")
	if baseDeleg == changedDeleg {
		t.Fatalf("delegation hash did not change after NS target changed below inline SOA")
	}
}

func TestParseZoneSecurityContinuationKeepsPreviousOwnerAcrossOrigin(t *testing.T) {
	continued := "$ORIGIN example.com.\n" +
		"@ IN NS ns1.example.net.\n" +
		"; comments must not reset the owner\n" +
		"$ORIGIN sub.example.com.\n" +
		"        IN NS ns2.example.net.\n"
	explicit := "$ORIGIN example.com.\n" +
		"@ IN NS ns1.example.net.\n" +
		"@ IN NS ns2.example.net.\n"

	_, continuedDeleg := parseZoneSecurity([]byte(continued), "example.com.")
	_, explicitDeleg := parseZoneSecurity([]byte(explicit), "example.com.")
	if continuedDeleg != explicitDeleg {
		t.Fatalf("continued owner across $ORIGIN parsed differently from explicit owner")
	}
}

func TestParseZoneSecurityQuotedParenthesisDoesNotHideRecords(t *testing.T) {
	base := "txt IN TXT \"literal ( parenthesis\"\n" +
		"example.com. IN NS ns1.example.net.\n"
	changed := "txt IN TXT \"literal ( parenthesis\"\n" +
		"example.com. IN NS ns2.example.net.\n"

	_, baseDeleg := parseZoneSecurity([]byte(base), "example.com.")
	_, changedDeleg := parseZoneSecurity([]byte(changed), "example.com.")
	if baseDeleg == changedDeleg {
		t.Fatalf("delegation hash did not change after NS target changed below quoted parenthesis")
	}
}

func TestParseZoneSecurityMultilineMXTargetChangesDelegation(t *testing.T) {
	base := "example.com. IN MX 10 (\n" +
		"    mail.example.com.\n" +
		")\n"
	changed := "example.com. IN MX 10 (\n" +
		"    mail.evil.test.\n" +
		")\n"

	_, baseDeleg := parseZoneSecurity([]byte(base), "example.com.")
	_, changedDeleg := parseZoneSecurity([]byte(changed), "example.com.")
	if baseDeleg == changedDeleg {
		t.Fatalf("delegation hash did not change after multi-line MX target moved")
	}
}

func TestParseZoneSecurityCanonicalizesDelegationWithoutHidingMoves(t *testing.T) {
	base := "Example.COM. IN NS NS1\n" +
		"example.com. IN NS ns1.example.com.\n" +
		"example.com. IN MX 010 Mail\n"
	same := "example.com. IN MX 10 mail.example.com.\n" +
		"example.com. IN NS ns1.example.com.\n"
	moved := "example.com. IN MX 10 mail.example.com.\n" +
		"example.com. IN NS ns2.evil.test.\n"

	baseSec, baseDeleg := parseZoneSecurity([]byte(base), "example.com.")
	sameSec, sameDeleg := parseZoneSecurity([]byte(same), "example.com.")
	if baseSec != sameSec || baseDeleg != sameDeleg {
		t.Fatalf("case, trailing-dot, duplicate, or MX-preference normalization changed hashes")
	}

	_, movedDeleg := parseZoneSecurity([]byte(moved), "example.com.")
	if baseDeleg == movedDeleg {
		t.Fatalf("delegation hash did not change after NS target moved")
	}
}

func TestParseZoneSecurityRootOriginCanonicalizesRelativeNames(t *testing.T) {
	base := "$ORIGIN .\n" +
		"Example.COM IN NS NS1.Example.COM\n" +
		"example.com IN MX 010 Mail.Example.COM\n"
	same := "example.com. IN MX 10 mail.example.com.\n" +
		"example.com. IN NS ns1.example.com.\n"
	moved := "$ORIGIN .\n" +
		"example.com IN NS ns2.evil.test\n" +
		"example.com IN MX 10 mail.example.com\n"

	baseSec, baseDeleg := parseZoneSecurity([]byte(base), "example.com.")
	sameSec, sameDeleg := parseZoneSecurity([]byte(same), "example.com.")
	if baseSec != sameSec || baseDeleg != sameDeleg {
		t.Fatalf("root-origin relative names parsed differently from absolute names")
	}

	_, movedDeleg := parseZoneSecurity([]byte(moved), "example.com.")
	if baseDeleg == movedDeleg {
		t.Fatalf("delegation hash did not change after root-origin NS target moved")
	}
}

func TestParseZoneSecurityMultiUnitTTLDoesNotHideDelegation(t *testing.T) {
	base := "example.com. 1h30m IN NS ns1.example.net.\n" +
		"example.com. 2w3d IN MX 010 mail.example.com.\n"
	same := "example.com. 5400 IN NS ns1.example.net.\n" +
		"example.com. 1468800 IN MX 10 mail.example.com.\n"
	moved := "example.com. 1h30m IN NS ns2.evil.test.\n" +
		"example.com. 2w3d IN MX 10 mail.example.com.\n"

	baseSec, baseDeleg := parseZoneSecurity([]byte(base), "example.com.")
	sameSec, sameDeleg := parseZoneSecurity([]byte(same), "example.com.")
	if baseSec != sameSec || baseDeleg != sameDeleg {
		t.Fatalf("multi-unit TTL changed the security fingerprint")
	}

	_, movedDeleg := parseZoneSecurity([]byte(moved), "example.com.")
	if baseDeleg == movedDeleg {
		t.Fatalf("delegation hash did not change after multi-unit TTL NS target moved")
	}
}
