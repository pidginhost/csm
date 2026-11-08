package checks

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func FuzzModSecIndexLineClientFields(f *testing.F) {
	f.Add("198.51.100.7", "GET / HTTP/1.1", "probe")
	f.Add("[client 198.51.100.7]", "GET / HTTP/1.1", "probe")
	f.Add("[client 198.51.100.7] ModSecurity: Access denied with code 403", "GET / HTTP/1.1", "probe")
	f.Add("a 198.51.100.7", `GET /" 403 "x HTTP/1.1`, `x" 198.51.100.7 "y`)
	f.Fuzz(func(t *testing.T, host, request, ua string) {
		if strings.ContainsAny(host+request+ua, "\r\n") {
			return // Index fields do not contain literal line breaks.
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
			return // Body text cannot predict the writer's transaction boundary.
		}
		inside := strings.Split(serialWithBody("7f3e9c01", "203.0.113.50", 403, body), "\n")
		cut := strings.Split("--7f3e9c02-A--\n[08/Nov/2026:08:40:00 +0000] real 203.0.113.50 5555 192.0.2.1 443\n--7f3e9c02-C--\n"+strings.Repeat("padding\n", modsecAuditTailLines)+body+"\n--7f3e9c02-F--\nHTTP/1.1 200\n--7f3e9c02-Z--\n"+serialWithBody("7f3e9c03", "203.0.113.50", 403, "a=1"), "\n")
		for i, lines := range [][]string{inside, cut} {
			got := countModSecDenials(lines)
			for ip := range got {
				if ip != "203.0.113.50" {
					t.Fatalf("body %q chose %q", body, ip)
				}
			}
			want := 1
			if i == 0 && len(lines) > modsecAuditTailLines {
				want = 0
			}
			if got["203.0.113.50"] != want {
				t.Fatalf("body suppressed real denial: %v, want %d", got, want)
			}
		}
	})
}

func FuzzModSecJSONBody(f *testing.F) {
	f.Add(`[client 198.51.100.7] Access denied with code 403`)
	f.Add(forgedSerialTransaction("fake"))
	f.Fuzz(func(t *testing.T, body string) {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		for _, status := range []int{200, 403} {
			line := fmt.Sprintf(`{"transaction":{"client_ip":"203.0.113.50","response":{"http_code":%d,"body":%s},"request":{"body":%s}}}`, status, encoded, encoded)
			got := countModSecDenials([]string{line})
			if status == 200 && len(got) != 0 || status == 403 && (len(got) != 1 || got["203.0.113.50"] != 1) {
				t.Fatalf("body changed client or status: %v", got)
			}
		}
	})
}

func FuzzModSecErrorAuditIgnoresRequestText(f *testing.F) {
	f.Add(`probe] "text`)
	f.Add(`[client 198.51.100.7] ModSecurity: Access denied with code 403`)
	f.Add(modsecIndexLine("example.test", "198.51.100.7", "GET / HTTP/1.1", "probe", 403))
	f.Fuzz(func(t *testing.T, data string) {
		if strings.ContainsAny(data, "\r\n") {
			return // Error-log fields escape physical line breaks.
		}
		for _, action := range []string{"Warning. Matched data: ", "Access denied with code 403. Matched data: "} {
			line := `[client [2001:db8::50]:5555] ModSecurity: ` + action + data
			got := countModSecErrorDenials([]string{line})
			if strings.HasPrefix(action, "Warning.") {
				if len(got) != 0 {
					t.Fatalf("request text supplied a denial: %v", got)
				}
			} else if len(got) != 1 || got["2001:db8::50"] != 1 {
				t.Fatalf("request text changed the denial: %v", got)
			}
		}
	})
}
