package checks

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestModSecMalformedIndexCannotFallBackToHostClient(t *testing.T) {
	for _, host := range []string{
		"[client 198.51.100.7]",
		"[client [2001:db8::7]:443]",
		"[client 198.51.100.7] ModSecurity: Access denied with code 403",
		"[client [2001:db8::7]:443] ModSecurity: Access denied with code 403",
	} {
		line := modsecIndexLine(host, "203.0.113.50", "GET / HTTP/1.1", "probe", 403)
		if got := countModSecDenials([]string{line}); len(got) != 0 {
			t.Errorf("malformed Host selected a client: %v", got)
		}
	}
}

func TestModSecBodyMarkersDoNotSuppressRealDenial(t *testing.T) {
	for _, section := range []string{"C", "I", "E"} {
		log := serialWithBody("real", "203.0.113.50", 403, forgedSerialTransaction("fake"))
		log = strings.Replace(log, "--real-C--", "--real-"+section+"--", 1)
		if got := countModSecDenials(strings.Split(log, "\n")); len(got) != 1 || got["203.0.113.50"] != 1 {
			t.Errorf("section %s suppressed real denial: %v", section, got)
		}
	}
}

func TestModSecOpenBodyDoesNotEraseEarlierClients(t *testing.T) {
	log := serialTransaction("earlier", "192.0.2.9", 403) +
		"--real-A--\n[08/Nov/2026:08:40:00 +0000] real 203.0.113.50 5555 192.0.2.1 443\n--real-C--\n" +
		forgedSerialTransaction("fake")
	if got := countModSecDenials(strings.Split(log, "\n")); len(got) != 1 || got["192.0.2.9"] != 1 {
		t.Fatalf("open body erased an earlier client: %v", got)
	}
}

func TestModSecTailWhollyInsideOpenBodyCannotForgeDenials(t *testing.T) {
	for _, body := range []string{
		strings.Repeat(forgedSerialTransaction("fake"), 30),
		strings.Repeat(modsecIndexLine("example.com", "198.51.100.7", "GET / HTTP/1.1", "probe", 403)+"\n", 30),
		strings.Repeat("[Sun Nov 08 08:40:00 2026] [security2:error] [client 198.51.100.7] ModSecurity: Access denied with code 403\n", 30),
	} {
		log := "--real-A--\n[08/Nov/2026:08:40:00 +0000] real 203.0.113.50 5555 192.0.2.1 443\n--real-C--\n" +
			strings.Repeat("body padding\n", modsecAuditTailLines) + body
		if got := auditFindingIPs(t, log); len(got) != 0 {
			t.Errorf("unframed body tail forged findings: %v", got)
		}
	}
}

func TestModSecNativeV3AndJSONDenials(t *testing.T) {
	// v3 omits the local-user column and uses a seconds-only timestamp.
	v3Index := `example.com 2001:db8::50 - [08/Nov/2026:08:40:00 +0000] "GET / HTTP/1.1" 403 199 - "probe" tx - /audit/tx 0 1234 md5:0123456789abcdef0123456789abcdef`
	for name, line := range map[string]string{
		"v3 concurrent": v3Index,
		"v3 JSON":       `{"transaction":{"client_ip":"2001:db8::50","response":{"http_code":403},"request":{"body":"[client 198.51.100.7] Access denied"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := countModSecDenials([]string{line}); len(got) != 1 || got["2001:db8::50"] != 1 {
				t.Fatalf("denials = %v, want the v3 client once", got)
			}
			if got := auditFindingIPs(t, strings.Repeat(line+"\n", 25)); len(got) != 1 || got[0] != "2001:db8::50" {
				t.Fatalf("v3 audit findings = %v, want the connecting client", got)
			}
		})
	}
}

func TestModSecJSONBodyCannotSupplyClientOrDenial(t *testing.T) {
	for _, status := range []int{200, 403} {
		line := fmt.Sprintf(`{"transaction":{"client_ip":"203.0.113.50","response":{"http_code":%d},"request":{"body":"[client 198.51.100.7] Access denied with code 403"}}}`, status)
		got := countModSecDenials([]string{line})
		if got["198.51.100.7"] != 0 || (status == 200 && len(got) != 0) || (status == 403 && got["203.0.113.50"] != 1) {
			t.Errorf("status %d: body supplied client or denial: %v", status, got)
		}
	}
}

func TestModSecResponseMetadataIsNotADenial(t *testing.T) {
	log := serialTransaction("real", "203.0.113.50", 200)
	log = strings.Replace(log, "Content-Type: text/html", "X-Request: 403 Access denied MODSEC", 1)
	log = strings.Replace(log, "Stopwatch: 1 2 (- - -)", "Message: Warning. Matched data: Access denied 403\nStopwatch: 1403 2 (- - -)", 1)
	if got := countModSecDenials(strings.Split(log, "\n")); len(got) != 0 {
		t.Fatalf("metadata counted as a denial: %v", got)
	}
}

func TestModSecNativeV3Serial(t *testing.T) {
	log := serialTransaction("-native--", "2001:db8::50", 403)
	// This is the v3 H line, including when F is not configured for logging.
	start, end := strings.Index(log, "---native---F--"), strings.Index(log, "---native---H--")
	log = log[:start] + log[end:]
	log = strings.Replace(log, "Message: Access denied", "ModSecurity: Access denied", 1)
	if got := countModSecDenials(strings.Split(log, "\n")); len(got) != 1 || got["2001:db8::50"] != 1 {
		t.Fatalf("native v3 H denial = %v", got)
	}
}

func TestModSecIndexDialectsCannotShiftClientColumn(t *testing.T) {
	line := `fake 198.51.100.7 203.0.113.50 - [08/Nov/2026:08:40:00 +0000] "GET / HTTP/1.1" 403 199 - "probe" tx - /audit/tx 0 1234.000000 md5:0123456789abcdef0123456789abcdef`
	if got := countModSecDenials([]string{line}); len(got) != 0 {
		t.Fatalf("whitespace in v3 Host switched to v2 client column: %v", got)
	}
}

func TestModSecIndexEscapedUserFieldsStillCountClient(t *testing.T) {
	line := modsecIndexLine("example.com", "203.0.113.50", "GET / HTTP/1.1", "probe", 403)
	line = strings.Replace(line, " - - [", ` - domain\user [`, 1)
	if got := countModSecDenials([]string{line}); len(got) != 1 || got["203.0.113.50"] != 1 {
		t.Fatalf("unquoted user field lost a real denial: %v", got)
	}
}

func TestModSecErrorLogUsesActionAndClientPrefix(t *testing.T) {
	for _, client := range []string{"203.0.113.50:5555", "[2001:db8::50]:5555"} {
		for _, action := range []string{"Warning. Matched Access denied with code 403", "Access denied with code 403"} {
			line := fmt.Sprintf(`[Sun Nov 08 08:40:00.000000 2026] [security2:error] [pid 123] [client %s] ModSecurity: %s [data "[client 198.51.100.7]"]`, client, action)
			got := countModSecErrorDenials([]string{line})
			want := map[string]int{}
			if strings.HasPrefix(action, "Access denied") {
				ip := "203.0.113.50"
				if strings.HasPrefix(client, "[") {
					ip = "2001:db8::50"
				}
				want[ip] = 1
			}
			if !maps.Equal(got, want) {
				t.Errorf("action %q: denials %v, want %v", action, got, want)
			}
		}
	}
}

func auditReaderFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	writeAuditReaderFile(t, path, content)
	withMockOS(t, &mockOS{open: os.Open})
	return path
}

func writeAuditReaderFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func assertAuditReaderCounts(t *testing.T, path string, want map[string]int) {
	t.Helper()
	got, nonempty := readModSecDenials(context.Background(), path, false)
	if !nonempty || !maps.Equal(got, want) {
		t.Fatalf("denials = %v, nonempty = %v; want %v", got, nonempty, want)
	}
}

func TestModSecAuditReaderPartialWritesAndConcurrentScans(t *testing.T) {
	first := serialTransaction("earlier", "192.0.2.9", 403)
	open := "--real-A--\n[08/Nov/2026:08:40:00 +0000] real 203.0.113.50 5555 192.0.2.1 443\n--real-C--\n"
	content := first + open + forgedSerialTransaction("fake") + "--real-F--\nHTTP/1.1 403"
	path := auditReaderFile(t, content)
	want := map[string]int{"192.0.2.9": 1}
	assertAuditReaderCounts(t, path, want)
	// The next scan must retain the real transaction, including its incomplete
	// last line, and must never count the complete transaction in its body.
	content += "\n--real-Z--\n"
	writeAuditReaderFile(t, path, content)
	want["203.0.113.50"] = 1
	var wg sync.WaitGroup
	results := make(chan map[string]int, 4)
	for range 4 {
		wg.Go(func() {
			counts, _ := readModSecDenials(context.Background(), path, false)
			results <- counts
		})
	}
	wg.Wait()
	close(results)
	for got := range results {
		if !maps.Equal(got, want) {
			t.Fatalf("concurrent scan counts %v, want %v", got, want)
		}
	}
	got, _ := readModSecDenials(context.Background(), path, false)
	clear(got)
	assertAuditReaderCounts(t, path, want)
}

func TestModSecAuditReaderRotationAndCopytruncate(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		t.Run(fmt.Sprintf("rotate=%v", rotate), func(t *testing.T) {
			old := serialTransaction("old", "192.0.2.9", 403)
			path := auditReaderFile(t, old)
			assertAuditReaderCounts(t, path, map[string]int{"192.0.2.9": 1})
			if rotate {
				if err := os.Rename(path, path+".1"); err != nil {
					t.Fatal(err)
				}
			}
			fresh := serialTransaction("new", "203.0.113.50", 403)
			writeAuditReaderFile(t, path, fresh+strings.Repeat("\n", len(old)))
			assertAuditReaderCounts(t, path, map[string]int{"203.0.113.50": 1})
			writeAuditReaderFile(t, path, "\n")
			assertAuditReaderCounts(t, path, map[string]int{})
		})
	}
}

func TestModSecEmptyCandidatePreservesActiveReader(t *testing.T) {
	path := auditReaderFile(t, serialTransaction("real", "203.0.113.50", 403))
	want := map[string]int{"203.0.113.50": 1}
	assertAuditReaderCounts(t, path, want)
	empty := path + ".empty"
	writeAuditReaderFile(t, empty, "")
	if got, nonempty := readModSecDenials(context.Background(), empty, false); nonempty || len(got) != 0 {
		t.Fatalf("empty candidate selected: %v", got)
	}
	// An empty earlier candidate must not force the active log to replay on
	// every scan. An unchanged log can finish within one cancellation check.
	ctx := &auditCancelContext{Context: context.Background(), remaining: 2}
	if got, _ := readModSecDenials(ctx, path, false); !maps.Equal(got, want) {
		t.Fatalf("empty candidate discarded the active cursor: %v", got)
	}
}

func TestModSecAuditReaderOversizedBodiesAndRecentWindow(t *testing.T) {
	log := serialWithBody("real", "203.0.113.50", 403,
		strings.Repeat("x", maxLogLineBytes+1)+"\n"+forgedSerialTransaction("fake"))
	path := auditReaderFile(t, log)
	assertAuditReaderCounts(t, path, map[string]int{"203.0.113.50": 1})
	lines := strings.Count(log, "\n")
	log += strings.Repeat("\n", modsecAuditTailLines-lines)
	writeAuditReaderFile(t, path, log)
	assertAuditReaderCounts(t, path, map[string]int{"203.0.113.50": 1})
	writeAuditReaderFile(t, path, log+"\n")
	assertAuditReaderCounts(t, path, map[string]int{})
}

func TestModSecAuditReaderCancelledScanKeepsFramedProgress(t *testing.T) {
	content := serialTransaction("old", "192.0.2.9", 403)
	path := auditReaderFile(t, content)
	assertAuditReaderCounts(t, path, map[string]int{"192.0.2.9": 1})
	content += serialTransaction("new", "203.0.113.50", 403)
	writeAuditReaderFile(t, path, content)
	ctx := &auditCancelContext{Context: context.Background(), remaining: 4}
	if counts, _ := readModSecDenials(ctx, path, false); len(counts) != 0 {
		t.Fatalf("cancelled scan returned %v", counts)
	}
	modsecAuditReader.Lock()
	checkpoint := modsecAuditReader.follow.Offset
	valid := modsecAuditReader.info != nil
	modsecAuditReader.Unlock()
	if !valid || checkpoint <= int64(len(serialTransaction("old", "192.0.2.9", 403))) || checkpoint >= int64(len(content)) {
		t.Fatalf("cancelled catch-up lost safe progress: valid=%v offset=%d", valid, checkpoint)
	}
	assertAuditReaderCounts(t, path, map[string]int{"192.0.2.9": 1, "203.0.113.50": 1})
	modsecAuditReader.Lock()
	defer modsecAuditReader.Unlock()
	if got := modsecAuditReader.parser.line; got != int64(strings.Count(content, "\n")) {
		t.Fatalf("cancelled scan advanced framing twice: line %d", got)
	}
}

type auditCancelContext struct {
	context.Context
	remaining int
}

func (c *auditCancelContext) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		return context.Canceled
	}
	return nil
}

// The parser starts at the beginning of a file, never at an unframed tail.
func countModSecDenials(lines []string) map[string]int {
	var p modsecAuditParser
	for _, line := range lines {
		p.feed(line, false)
	}
	return p.blocked
}

func TestModSecErrorLogIPv6ClientDropsPort(t *testing.T) {
	ip, denied := modsecErrorLogDenial("[Tue Apr 14 10:00:00 2026] [security2:error] [client 2001:db8::5:5555] ModSecurity: Access denied with code 403")
	if ip != "2001:db8::5" || !denied {
		t.Fatalf("modsecErrorLogDenial = %q, %v; want 2001:db8::5, true", ip, denied)
	}
}

func countModSecErrorDenials(lines []string) map[string]int {
	p := modsecAuditParser{errorLog: true}
	for _, line := range lines {
		p.feed(line, false)
	}
	return p.blocked
}
