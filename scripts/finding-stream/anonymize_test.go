package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
)

func testSalt() []byte { return bytes.Repeat([]byte{0x42}, 32) }

func sampleEvents() []alert.AuditEvent {
	ts := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	return []alert.AuditEvent{
		{
			V: 1, Timestamp: ts, FindingID: "f1", Severity: "CRITICAL", Check: "db_rogue_admin",
			Message:  "New WordPress admin account created in last 7 days: intruder on alice",
			Details:  "Account: alice\nPath: /home/alice/public_html\nRow: 9\tintruder\tintruder@example.net",
			Hostname: "srv.example.com", TenantID: "alice",
		},
		{
			V: 1, Timestamp: ts.Add(time.Minute), FindingID: "f2", Severity: "HIGH", Check: "email_rate_warning",
			Message:  "Email rate WARNING: sales@example.com sent 20 messages",
			Details:  "User: sales@example.com\nIP: 203.0.113.9",
			Hostname: "srv.example.com", Domain: "example.com", Mailbox: "sales@example.com", TenantID: "bob",
		},
		{
			V: 1, Timestamp: ts.Add(2 * time.Minute), FindingID: "f3", Severity: "CRITICAL", Check: "auto_block",
			Message:  "AUTO-BLOCK: 198.51.100.7 blocked (expires in 24h0m0s)",
			Details:  "Reason: 20+ denies from 198.51.100.7 and 2001:db8:1::7 within 4h0m0s",
			Hostname: "srv.example.com",
		},
		{
			V: 1, Timestamp: ts.Add(3 * time.Minute), FindingID: "f4", Severity: "CRITICAL", Check: "yara_match_scheduled",
			Message:  "YARA rule match [webshell_generic]: /home/carol/www.example.org/wp-content/plugins/x/wp-config.php",
			FilePath: "/home/carol/www.example.org/wp-content/plugins/x/wp-config.php",
			Hostname: "srv.example.com",
			Process: &processctx.ProcessContext{
				PID: 4242, UID: 1003, User: "carol", Account: "carol", Comm: "php-fpm",
				Exe: "/opt/cpanel/ea-php82/root/usr/sbin/php-fpm", Cmdline: []string{"php-fpm: pool carol"},
			},
		},
		{
			V: 1, Timestamp: ts.Add(4 * time.Minute), FindingID: "f5", Severity: "CRITICAL", Check: "email_credential_leak",
			Message:  "SMTP credentials leaked in email subject from user@example.com",
			Details:  "Subject: smtp.example.org:587,user@example.com,hunter2",
			Hostname: "srv.example.com", Mailbox: "user@example.com", Domain: "example.com",
		},
	}
}

func anonymizeAll(t *testing.T, salt []byte, events []alert.AuditEvent) ([]alert.AuditEvent, *Anonymizer) {
	t.Helper()
	a := NewAnonymizer(salt)
	a.Learn(events)
	out := make([]alert.AuditEvent, 0, len(events))
	for _, e := range events {
		out = append(out, a.Event(e))
	}
	return out, a
}

func TestAnonymizerReplacesStructuredIdentitiesDeterministically(t *testing.T) {
	first, _ := anonymizeAll(t, testSalt(), sampleEvents())
	second, _ := anonymizeAll(t, testSalt(), sampleEvents())
	for i := range first {
		if !equalEvents(first[i], second[i]) {
			t.Fatalf("event %d differs between runs with the same salt", i)
		}
	}
	other, _ := anonymizeAll(t, bytes.Repeat([]byte{0x99}, 32), sampleEvents())
	if other[0].TenantID == first[0].TenantID {
		t.Fatal("different salts produced the same pseudonym")
	}

	e := first[0]
	if !strings.HasPrefix(e.TenantID, "acct-") || e.TenantID == "alice" {
		t.Fatalf("tenant = %q", e.TenantID)
	}
	if e.Hostname == "srv.example.com" || !strings.HasPrefix(e.Hostname, "host-") {
		t.Fatalf("hostname = %q", e.Hostname)
	}
	if e.FindingID != "f1" || !e.Timestamp.Equal(sampleEvents()[0].Timestamp) || e.Check != "db_rogue_admin" || e.Severity != "CRITICAL" {
		t.Fatalf("non-identity fields changed: %+v", e)
	}
	mail := first[1]
	if !strings.HasSuffix(mail.Domain, ".example") || mail.Domain == "example.com" {
		t.Fatalf("domain = %q", mail.Domain)
	}
	if !strings.HasPrefix(mail.Mailbox, "user-") || !strings.HasSuffix(mail.Mailbox, "@"+mail.Domain) {
		t.Fatalf("mailbox = %q does not share the domain pseudonym %q", mail.Mailbox, mail.Domain)
	}
	if first[1].TenantID == first[0].TenantID {
		t.Fatal("distinct accounts collapsed to one pseudonym")
	}
}

func TestAnonymizerScrubsFreeTextAndPaths(t *testing.T) {
	out, a := anonymizeAll(t, testSalt(), sampleEvents())
	acct := a.Account("alice")
	if !strings.Contains(out[0].Message, acct) || strings.Contains(out[0].Message, "alice") {
		t.Fatalf("message keeps the raw account: %q", out[0].Message)
	}
	if !strings.Contains(out[0].Details, "/home/"+acct+"/public_html") || strings.Contains(out[0].Details, "intruder@example.net") {
		t.Fatalf("details not scrubbed: %q", out[0].Details)
	}
	if strings.Contains(out[1].Details, "203.0.113.9") || strings.Contains(out[1].Message, "sales@example.com") {
		t.Fatalf("mail text not scrubbed: %q %q", out[1].Message, out[1].Details)
	}
	if !strings.Contains(out[1].Message, out[1].Mailbox) {
		t.Fatalf("mailbox pseudonym in text %q differs from field %q", out[1].Message, out[1].Mailbox)
	}
	if strings.Contains(out[2].Message, "198.51.100.7") || strings.Contains(out[2].Details, "2001:db8:1::7") {
		t.Fatalf("addresses not scrubbed: %q %q", out[2].Message, out[2].Details)
	}
	ip := a.IPv4("198.51.100.7")
	if !strings.Contains(out[2].Message, ip) || !strings.Contains(out[2].Details, ip) {
		t.Fatalf("the same address must map to one pseudonym in message %q and details %q", out[2].Message, out[2].Details)
	}
	if !strings.HasPrefix(ip, "198.18.") && !strings.HasPrefix(ip, "198.19.") {
		t.Fatalf("IPv4 pseudonym %q is outside the benchmarking range", ip)
	}
	if !strings.HasPrefix(a.IPv6("2001:db8:1::7"), "2001:db8:") {
		t.Fatalf("IPv6 pseudonym %q is outside the documentation prefix", a.IPv6("2001:db8:1::7"))
	}

	path := out[3].FilePath
	carol := a.Account("carol")
	if !strings.HasPrefix(path, "/home/"+carol+"/") || strings.Contains(path, "carol") || strings.Contains(path, "example.org") {
		t.Fatalf("path not scrubbed: %q", path)
	}
	if !strings.HasSuffix(path, "/wp-content/plugins/x/wp-config.php") {
		t.Fatalf("path structure or file names changed: %q", path)
	}
	if out[3].Message != "YARA rule match [webshell_generic]: "+path {
		t.Fatalf("message path %q disagrees with file_path %q", out[3].Message, path)
	}
	p := out[3].Process
	if p == nil || p.Account != carol || p.User != carol || p.Comm != "php-fpm" || p.PID != 4242 {
		t.Fatalf("process context = %+v", p)
	}
	if len(p.Cmdline) != 1 || strings.Contains(p.Cmdline[0], "carol") {
		t.Fatalf("cmdline not scrubbed: %v", p.Cmdline)
	}
}

func TestAnonymizerRedactsCredentialMaterial(t *testing.T) {
	out, _ := anonymizeAll(t, testSalt(), sampleEvents())
	leak := out[4]
	if strings.Contains(leak.Details, "hunter2") || strings.Contains(leak.Details, "example.org") {
		t.Fatalf("credential leak details kept material: %q", leak.Details)
	}
	if !strings.Contains(leak.Details, "[redacted]") {
		t.Fatalf("credential leak details not marked redacted: %q", leak.Details)
	}
	generic := alert.AuditEvent{V: 1, Check: "webshell", Message: "x", Details: "found password=Sup3rSecret and token: abcDEF123 in config", Hostname: "h"}
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{generic})
	got := a.Event(generic).Details
	if strings.Contains(got, "Sup3rSecret") || strings.Contains(got, "abcDEF123") {
		t.Fatalf("generic secret patterns survived: %q", got)
	}
}

func TestAnonymizerLeaksAreDetected(t *testing.T) {
	events := sampleEvents()
	out, a := anonymizeAll(t, testSalt(), events)
	if problems := a.Verify(out); len(problems) != 0 {
		t.Fatalf("clean output reported leaks: %v", problems)
	}
	planted := out
	planted[0].Details += " see alice at 203.0.113.9 and sales@example.com on srv.example.com"
	problems := a.Verify(planted)
	for _, want := range []string{"alice", "203.0.113.9", "example.com", "srv.example.com"} {
		found := false
		for _, p := range problems {
			if strings.Contains(p, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("leak of %q not detected in %v", want, problems)
		}
	}
}

func TestAnonymizerLeavesFileExtensionsAlone(t *testing.T) {
	e := alert.AuditEvent{V: 1, Check: "webshell", Message: "found wp-config.php and index.html near data.tar.gz", Hostname: "h"}
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{e})
	got := a.Event(e).Message
	if got != e.Message {
		t.Fatalf("file names treated as domains: %q", got)
	}
}

func TestRunAnonymizesFilesEndToEnd(t *testing.T) {
	dir := t.TempDir()
	var raw bytes.Buffer
	for _, e := range sampleEvents() {
		b, _ := json.Marshal(e)
		raw.Write(b)
		raw.WriteByte('\n')
	}
	plain := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(plain, raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	gzPath := filepath.Join(dir, "audit.jsonl-20260907.gz")
	f, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err = zw.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	saltPath := filepath.Join(dir, "salt")
	outPath := filepath.Join(dir, "out", "alice.example.com.jsonl.gz")
	var stdout bytes.Buffer
	if err = run([]string{"anonymize", "--salt-file", saltPath, "--out", outPath, plain, gzPath}, &stdout); err != nil {
		t.Fatalf("run: %v\n%s", err, stdout.String())
	}
	info, err := os.Stat(saltPath)
	if err != nil || info.Mode().Perm() != 0o600 || info.Size() < 32 {
		t.Fatalf("salt file %v %v", info, err)
	}
	outFile, err := os.Open(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer outFile.Close()
	zr, err := gzip.NewReader(outFile)
	if err != nil {
		t.Fatal(err)
	}
	body, err := readAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2*len(sampleEvents()) {
		t.Fatalf("output has %d lines, want %d", len(lines), 2*len(sampleEvents()))
	}
	for _, raw := range []string{"alice", "carol", "example.com", "example.org", "203.0.113.9", "198.51.100.7", "hunter2", "srv.example.com"} {
		if strings.Contains(string(body), raw) {
			t.Errorf("output contains raw identifier %q", raw)
		}
	}
	manifest := stdout.String()
	for _, want := range []string{"events: 10", "db_rogue_admin", "salt fingerprint:"} {
		if !strings.Contains(manifest, want) {
			t.Errorf("summary lacks %q:\n%s", want, manifest)
		}
	}
	if strings.Contains(manifest, "alice") || strings.Contains(manifest, "example.com") {
		t.Errorf("summary leaks an identifier:\n%s", manifest)
	}

	// A second run with the same salt maps identically, so streams from
	// different hosts can be joined on pseudonyms.
	var again bytes.Buffer
	outAgain := filepath.Join(dir, "out", "again.jsonl.gz")
	if err := run([]string{"anonymize", "--salt-file", saltPath, "--out", outAgain, plain}, &again); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(again.String(), "salt fingerprint: "+fingerprintFrom(manifest)) {
		t.Fatalf("salt fingerprint changed between runs:\n%s\n%s", manifest, again.String())
	}
}

func fingerprintFrom(summary string) string {
	for _, line := range strings.Split(summary, "\n") {
		if strings.HasPrefix(line, "salt fingerprint: ") {
			return strings.TrimPrefix(line, "salt fingerprint: ")
		}
	}
	return ""
}

func equalEvents(a, b alert.AuditEvent) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}

// LiteSpeed vhost tokens glue addresses, the account and the domain together
// with underscores, which are word characters to a regexp: identities after
// an underscore must still be replaced and still be caught by Verify.
func TestAnonymizerScrubsUnderscoreDelimitedIdentities(t *testing.T) {
	e := alert.AuditEvent{
		V: 1, Check: "modsec_classifier_gap", Severity: "MEDIUM",
		Message:  "ModSecurity rule 217200 from 203.0.113.9 is unclassified",
		Details:  "[203.0.113.9:33886:HTTP2-1#APVH_127.0.0.1:443_198.51.100.7:443_alice_www.example.com] rule at [02_Global_Generic.conf:60] vhost APVH_*_example.org on host7 db wp_options.option_value",
		Hostname: "host7.example.com", TenantID: "alice", Domain: "example.com",
	}
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{e})
	got := a.Event(e)
	for _, raw := range []string{"alice", "example.com", "example.org", "203.0.113.9", "198.51.100.7", "host7"} {
		if strings.Contains(got.Details, raw) || strings.Contains(got.Message, raw) {
			t.Errorf("%q survived: %q", raw, got.Details)
		}
	}
	if !strings.Contains(got.Details, "_"+a.Account("alice")+"_"+a.Domain("www.example.com")+"]") {
		t.Errorf("vhost token not rewritten in place: %q", got.Details)
	}
	if !strings.Contains(got.Details, "APVH_127.0.0.1:443_"+a.IPv4("198.51.100.7")+":443_") || !strings.Contains(got.Details, "02_Global_Generic.conf:60") {
		t.Errorf("loopback, addresses or file names mishandled: %q", got.Details)
	}
	if problems := a.Verify([]alert.AuditEvent{got}); len(problems) != 0 {
		t.Fatalf("clean output reported leaks: %v", problems)
	}
	problems := a.Verify([]alert.AuditEvent{e})
	joined := strings.Join(problems, "\n")
	for _, want := range []string{"account alice", "domain example.com", "host host7.example.com", "host host7", "ipv4 198.51.100.7", "ipv4 203.0.113.9"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Verify missed %q in raw event: %v", want, problems)
		}
	}
}

func TestVerifyBoundariesIgnoreWordsContainingNames(t *testing.T) {
	learned := alert.AuditEvent{V: 1, Check: "x", Hostname: "web7.example.com", TenantID: "alice", Domain: "alice.example.com"}
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{learned})
	clean := alert.AuditEvent{V: 1, Check: "x", Message: "web77 webshell malice 127.0.0.1", Hostname: a.Host("web7.example.com")}
	if problems := a.Verify([]alert.AuditEvent{clean}); len(problems) != 0 {
		t.Fatalf("words containing learned names reported as leaks: %v", problems)
	}
	// A domain-shaped word must be refused, without attributing a suffix
	// inside one of its labels to a different learned domain or account.
	words := strings.Join(a.Verify([]alert.AuditEvent{{Message: "malice.example.com"}}), "\n")
	if !strings.Contains(words, "domain malice.example.com") || strings.Contains(words, "domain alice.example.com") || strings.Contains(words, "account alice") {
		t.Fatalf("domain boundaries misclassified: %s", words)
	}
	if a.Host("web7") != a.Host("web7.example.com") {
		t.Fatal("host alias maps to a different pseudonym than the full name")
	}
	dirty := alert.AuditEvent{V: 1, Check: "x", Message: "user alice on www.alice.example.com via web7", Hostname: a.Host("web7.example.com")}
	problems := strings.Join(a.Verify([]alert.AuditEvent{dirty}), "\n")
	for _, want := range []string{"account alice", "domain alice.example.com", "host web7"} {
		if !strings.Contains(problems, want) {
			t.Errorf("Verify missed %q: %s", want, problems)
		}
	}
}

func TestAnonymizerScrubsSecretsAfterUnderscore(t *testing.T) {
	e := alert.AuditEvent{V: 1, Check: "x", Details: "db_password=Sup3rSecret api_key: k-123 ok", Hostname: "h"}
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{e})
	got := a.Event(e).Details
	if strings.Contains(got, "Sup3rSecret") || strings.Contains(got, "k-123") {
		t.Fatalf("secret after underscore survived: %q", got)
	}
}

func BenchmarkTextWithManyLearnedNames(b *testing.B) {
	var events []alert.AuditEvent
	for i := 0; i < 300; i++ {
		events = append(events, alert.AuditEvent{V: 1, Check: "x", TenantID: fmt.Sprintf("acct%03d", i), Domain: fmt.Sprintf("site%03d.example.net", i), Hostname: "host7.example.com"})
	}
	a := NewAnonymizer(testSalt())
	a.Learn(events)
	text := "[203.0.113.9:33886:HTTP2-1#APVH_127.0.0.1:443_198.51.100.7:443_acct042_site042.example.net] mod_security rule [id \"217200\"] at [/etc/apache2/conf.d/modsec_vendor_configs/comodo_litespeed/02_Global_Generic.conf:60] triggered on /home/acct042/public_html/wp-content/plugins/x/y.php"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Text(text)
	}
}

// Names survive inside file names and ranges: a domain log, a host log, an
// address range. Numeric suffixes must not hide an address in a rotated log.
func TestAnonymizerScrubsNamesInsideLongerTokens(t *testing.T) {
	e := alert.AuditEvent{
		V: 1, Check: "modsec_low_confidence_burst",
		Details:  "logs /var/log/apache2/domlogs/example.com-ssl_log and /var/log/cluster6.log and Example.COM.conf; range 203.0.113.9-198.51.100.7; agent Chrome/203.0.113.9.1",
		Hostname: "cluster6.example.net", Domain: "example.com",
	}
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{e})
	got := a.Event(e).Details
	for _, raw := range []string{"example.com", "Example.COM", "cluster6", "203.0.113.9", "198.51.100.7"} {
		if strings.Contains(got, raw) {
			t.Errorf("%q survived: %q", raw, got)
		}
	}
	dom := a.Domain("example.com")
	for _, want := range []string{"domlogs/" + dom + "-ssl_log", "/var/log/" + a.Host("cluster6.example.net") + ".log", dom + ".conf", a.IPv4("203.0.113.9") + "-" + a.IPv4("198.51.100.7"), "Chrome/" + a.IPv4("203.0.113.9") + ".1"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if problems := a.Verify([]alert.AuditEvent{a.Event(e)}); len(problems) != 0 {
		t.Fatalf("clean output reported leaks: %v", problems)
	}
	raw := strings.Join(a.Verify([]alert.AuditEvent{e}), "\n")
	for _, want := range []string{"domain example.com", "host cluster6", "ipv4 203.0.113.9", "ipv4 198.51.100.7"} {
		if !strings.Contains(raw, want) {
			t.Errorf("Verify missed %q: %s", want, raw)
		}
	}
}

func TestLearnRejectsFileNamesAndNumbers(t *testing.T) {
	e := alert.AuditEvent{
		V: 1, Check: "php_remote_taint",
		Message:  "tainted call in module.php",
		FilePath: "/home/alice/public_html/wp-content/themes/x/home/module.php",
		Process:  &processctx.ProcessContext{PID: 7, UID: 1003, User: "1003", Account: "alice"},
	}
	a := NewAnonymizer(testSalt())
	a.Learn([]alert.AuditEvent{e})
	for _, bad := range []string{"module.php", "1003"} {
		if _, ok := a.accounts[bad]; ok {
			t.Errorf("%q learned as an account", bad)
		}
	}
	if _, ok := a.accounts["alice"]; !ok {
		t.Fatal("alice not learned")
	}
	got := a.Event(e)
	if got.Process.User != "1003" || got.Process.PID != 7 {
		t.Errorf("numeric user or pid changed: %+v", got.Process)
	}
	if got.Message != "tainted call in module.php" || strings.Contains(got.FilePath, "alice") {
		t.Errorf("message %q path %q", got.Message, got.FilePath)
	}
	if problems := a.Verify([]alert.AuditEvent{got}); len(problems) != 0 {
		t.Fatalf("clean output reported leaks: %v", problems)
	}
}
