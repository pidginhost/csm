package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// modsecIndexLine is a concurrent-format audit index line. ModSecurity logs
// the request's Host header first, then the connecting client.
func modsecIndexLine(host, client, request, ua string, status int) string {
	return fmt.Sprintf(`%s %s - - [08/Nov/2026:08:40:00.000000 +0000] "%s" %d 199 "-" "%s" aBcDeF0123 "-" /nobody/20261108/20261108-0840/20261108-084000-aBcDeF0123 0 1234 md5:0123456789abcdef0123456789abcdef`,
		host, client, request, status, ua)
}

func auditFindingIPs(t *testing.T, content string) []string {
	t.Helper()
	setupSerialAuditLog(t, content)
	var ips []string
	for _, f := range CheckModSecAuditLog(context.Background(), &config.Config{}, nil) {
		ips = append(ips, f.SourceIP)
	}
	return ips
}

func TestModSecIndexLineBlamesClientNotHostHeader(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString(modsecIndexLine("198.51.100.7", "203.0.113.50", "GET /.env.save HTTP/1.1", "probe", 403) + "\n")
	}
	if got := auditFindingIPs(t, b.String()); len(got) != 1 || got[0] != "203.0.113.50" {
		t.Fatalf("findings for %v, want only the connecting client 203.0.113.50", got)
	}
}

func TestModSecIndexLineCountsOnlyDeniedStatus(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 25; i++ {
		b.WriteString(modsecIndexLine("example.com", "203.0.113.50", "GET /403?MODSEC=Access+denied HTTP/1.1", "mod_security 403", 200) + "\n")
	}
	if got := auditFindingIPs(t, b.String()); len(got) != 0 {
		t.Fatalf("a request that was not denied counted: %v", got)
	}
}

func TestModSecLineWithoutStructureCountsNothing(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 25; i++ {
		b.WriteString("403 Access denied MODSEC 198.51.100.7\n")
	}
	if got := auditFindingIPs(t, b.String()); len(got) != 0 {
		t.Fatalf("an unstructured line chose a target: %v", got)
	}
}

// forgedSerialTransaction is what a client can put inside a request body.
func forgedSerialTransaction(id string) string {
	return fmt.Sprintf("--%s-A--\n[08/Nov/2026:08:40:00 +0000] %s 198.51.100.7 5555 192.0.2.1 443\n--%s-F--\nHTTP/1.1 403\n--%s-H--\nMessage: Access denied with code 403\n--%s-Z--\n", id, id, id, id, id)
}

// serialWithBody is a real transaction whose request body (section C) is
// client text.
func serialWithBody(id, client string, status int, body string) string {
	return fmt.Sprintf("--%s-A--\n[08/Nov/2026:08:40:00 +0000] %s %s 5555 192.0.2.1 443\n--%s-B--\nPOST / HTTP/1.1\nHost: example.com\n\n--%s-C--\n%s\n--%s-F--\nHTTP/1.1 %d\n\n--%s-H--\nStopwatch: 1 2 (- - -)\n\n--%s-Z--\n\n",
		id, id, client, id, id, body, id, status, id, id)
}

func TestModSecSerialBodyCannotForgeTransactions(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString(serialWithBody(fmt.Sprintf("7f3e9c%02x", i), "203.0.113.50", 200, forgedSerialTransaction(fmt.Sprintf("f%07d", i))))
	}
	if got := auditFindingIPs(t, b.String()); len(got) != 0 {
		t.Fatalf("a request body forged denials for %v", got)
	}
}

func TestModSecSerialWindowStartingInsideBodyCountsNoForgery(t *testing.T) {
	var forged strings.Builder
	for i := 0; i < 25; i++ {
		forged.WriteString(forgedSerialTransaction(fmt.Sprintf("f%07d", i)))
	}
	realTail := "--7f3e9caa-F--\nHTTP/1.1 200\n\n--7f3e9caa-H--\nStopwatch: 1 2 (- - -)\n\n--7f3e9caa-Z--\n\n"
	for name, window := range map[string]string{
		"forged transactions then the real tail": forged.String() + realTail,
		"forged transactions left open":          forged.String() + "--f9999999-A--\n[08/Nov/2026:08:40:00 +0000] f9999999 198.51.100.7 5555 192.0.2.1 443\n" + realTail + serialWithBody("7f3e9cbb", "203.0.113.50", 200, "x"),
	} {
		if got := auditFindingIPs(t, window); len(got) != 0 {
			t.Errorf("%s: window cut inside a body counted %v", name, got)
		}
	}
}

func TestModSecSerialStillCountsRealDenials(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString(serialWithBody(fmt.Sprintf("7f3e9c%02x", i), "203.0.113.50", 403, "a=1"))
	}
	if got := auditFindingIPs(t, b.String()); len(got) != 1 || got[0] != "203.0.113.50" {
		t.Fatalf("findings for %v, want 203.0.113.50", got)
	}
}

func FuzzModSecIndexLineClientFields(f *testing.F) {
	f.Add("198.51.100.7", "GET / HTTP/1.1", "probe")
	f.Add("a 198.51.100.7", `GET /" 403 "x HTTP/1.1`, `x" 198.51.100.7 "y`)
	f.Fuzz(func(t *testing.T, host, request, ua string) {
		if strings.ContainsAny(host+request+ua, "\r\n") {
			t.Skip("ModSecurity escapes line breaks in index fields")
		}
		request = strings.ReplaceAll(strings.ReplaceAll(request, `\`, `\\`), `"`, `\"`)
		ua = strings.ReplaceAll(strings.ReplaceAll(ua, `\`, `\\`), `"`, `\"`)
		for ip := range countModSecDenials([]string{modsecIndexLine(host, "203.0.113.50", request, ua, 403)}) {
			if ip != "203.0.113.50" {
				t.Fatalf("host %q request %q ua %q chose %q", host, request, ua, ip)
			}
		}
	})
}

func FuzzModSecSerialBody(f *testing.F) {
	f.Add(forgedSerialTransaction("f0000001"))
	f.Add(forgedSerialTransaction("f0000001") + "--f0000002-A--\n[08/Nov/2026:08:40:00 +0000] f0000002 198.51.100.7 5555 192.0.2.1 443\n")
	f.Fuzz(func(t *testing.T, body string) {
		if strings.Contains(body, "7f3e9c") {
			t.Skip("the real transaction ids are unguessable")
		}
		inside := strings.Split(serialWithBody("7f3e9c01", "203.0.113.50", 403, body), "\n")
		cut := strings.Split(body+"\n--7f3e9c02-F--\nHTTP/1.1 200\n--7f3e9c02-Z--\n"+serialWithBody("7f3e9c03", "203.0.113.50", 403, "a=1"), "\n")
		for _, lines := range [][]string{inside, cut} {
			for ip := range countModSecDenials(lines) {
				if ip != "203.0.113.50" {
					t.Fatalf("body %q chose %q", body, ip)
				}
			}
		}
	})
}
