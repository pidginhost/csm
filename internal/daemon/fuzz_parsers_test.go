package daemon

import (
	"testing"
)

// Fuzz targets for daemon-side log parsers. Same approach as
// internal/checks/fuzz_parsers_test.go: find crashers, don't verify output.

func FuzzParseDovecotLoginFields(f *testing.F) {
	f.Add("... Login: user=<alice@example.com>, method=PLAIN, rip=1.2.3.4, lip=10.0.0.1")
	f.Add("Login: user=<alice>, rip=1.2.3.4")
	f.Add("no login here")
	f.Add("user=<")
	f.Add("user=<unclosed")
	f.Add("rip=")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = parseDovecotLoginFields(line)
	})
}

func FuzzExtractMailHoldSender(f *testing.F) {
	f.Add("Sender user@domain has an outgoing mail hold")
	f.Add("Domain example.com has an outgoing mail hold")
	f.Add("Sender ")
	f.Add("Domain ")
	f.Add("no sender marker")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		_ = extractMailHoldSender(line)
	})
}

func FuzzExtractBracketedIP(f *testing.F) {
	f.Add("H=client [203.0.113.50]:2222 auth failed")
	f.Add("[1.2.3.4]")
	f.Add("no bracket")
	f.Add("[unclosed")
	f.Add("[][]")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		_ = extractBracketedIP(line)
	})
}

func FuzzExtractSetID(f *testing.F) {
	f.Add("(set_id=user@domain)")
	f.Add("(set_id=user)")
	f.Add("(set_id=")
	f.Add("no set_id here")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		_ = extractSetID(line)
	})
}

func FuzzParseSPFDMARCRejection(f *testing.F) {
	f.Add("2024-01-01 H=mail [203.0.113.5] F=<a@evil.com> ** <b@victim.com> : SPF check failed")
	f.Add("R=dnslookup ** <user@example.com> : 5.7.1 DMARC alignment failure")
	f.Add(" ** <user@example.com> : DKIM signature invalid")
	f.Add(" ** <@nodomain> : spf")
	f.Add(" ** <user@> : dmarc")
	f.Add(" ** <user@domain>")
	f.Add(" ** no brackets : spf")
	f.Add("no star marker at all")
	f.Add(" ** <a@b> : ")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = parseSPFDMARCRejection(line)
	})
}

func FuzzExtractPureFTPDClientIP(f *testing.F) {
	f.Add("pure-ftpd: (?@203.0.113.5) [INFO] Login failed")
	f.Add("pure-ftpd: (user@2001:db8::1) [INFO] ok")
	f.Add("(noatsign)")
	f.Add("(user@not-an-ip)")
	f.Add("(user@203.0.113.5")
	f.Add("user@203.0.113.5)")
	f.Add("(@)")
	f.Add("plain log line")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		_ = extractPureFTPDClientIP(line)
	})
}

func FuzzIsPrivateOrLoopback(f *testing.F) {
	f.Add("127.0.0.1")
	f.Add("10.0.0.5")
	f.Add("172.16.1.1")
	f.Add("192.168.1.1")
	f.Add("203.0.113.1")
	f.Add("2001:db8::1")
	f.Add("::1")
	f.Add("not-an-ip")
	f.Add("")
	f.Fuzz(func(t *testing.T, ip string) {
		_ = isPrivateOrLoopback(ip)
	})
}
