//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"testing"
)

// CSM's replacement for the suppressed Forge rule ELCEEF_HTML_Smuggling_A.
// That rule counted a payload marker set in which the generic JavaScript idiom
// `.charCodeAt(i)^` counted as a smuggled payload, so ordinary bundles that
// offer a client-side download (Google Analytics for WordPress, LiteSpeed cache
// output) were reported as HTML smuggling. Smuggling means a payload is carried
// in the page, so the replacement requires the encoded file header itself.

// benignDownloadBundle is the real FP shape: blob assembly, msSaveBlob, atob
// and a charCodeAt XOR hash, with nothing smuggled.
const benignDownloadBundle = `function x(p){for(var h=0,i=0;i<p.length;i++)h=(h<<5)-h+p.charCodeAt(i)^0;return h}` +
	`function dl(d,n){var b=new Blob([new Uint8Array(atob(d).split("").map(function(c){return c.charCodeAt(0)}))],` +
	`{type:"application/octet-stream"});if(window.navigator.msSaveBlob){window.navigator.msSaveBlob(b,n);return}` +
	`var a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=n;a.click()}`

func TestHTMLSmuggling_BenignDownloadBundle(t *testing.T) {
	s := loadRepoYaraScanner(t)
	if hasYaraRule(s.ScanBytes([]byte(benignDownloadBundle)), "html_smuggling_payload") {
		t.Error("html_smuggling_payload FP: matched a bundle that downloads generated data and smuggles nothing")
	}
}

func TestHTMLSmuggling_EmbeddedExecutableDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	// Base64 of an MZ/PE header carried in the page and reassembled to a file.
	mal := []byte(`<html><script>var p="TVqQAAMAAAAEAAAA//8AALgAAAA";` +
		`var b=new Blob([new Uint8Array(atob(p).split("").map(c=>c.charCodeAt(0)))],{type:"application/octet-stream"});` +
		`var a=document.createElement("a");a.href=URL.createObjectURL(b);a.download="invoice.exe";a.click();</script></html>`)
	if !hasYaraRule(s.ScanBytes(mal), "html_smuggling_payload") {
		t.Error("html_smuggling_payload regression: base64 PE payload reassembled into a download not detected")
	}
}

func TestHTMLSmuggling_EmbeddedOfficeDocDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<html><script>var d="0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAA";` +
		`var blob=new Blob([new Uint8Array(atob(d).split("").map(function(c){return c.charCodeAt(0)}))]);` +
		`var l=document.createElement("a");l.href=window.URL.createObjectURL(blob);l.download="report.doc";l.click();</script></html>`)
	if !hasYaraRule(s.ScanBytes(mal), "html_smuggling_payload") {
		t.Error("html_smuggling_payload regression: base64 OLE2 document payload not detected")
	}
}

func TestHTMLSmuggling_EmbeddedZipViaMsSaveBlobDetected(t *testing.T) {
	s := loadRepoYaraScanner(t)
	mal := []byte(`<html><script>var z="UEsDBAoAAAAAAHtbAAAAAAAA";` +
		`var b=new Blob([new Uint8Array(atob(z).split("").map(c=>c.charCodeAt(0)))],{type:"application/zip"});` +
		`window.navigator.msSaveBlob(b,"docs.zip");</script></html>`)
	if !hasYaraRule(s.ScanBytes(mal), "html_smuggling_payload") {
		t.Error("html_smuggling_payload regression: base64 ZIP payload saved via msSaveBlob not detected")
	}
}

// A page that merely mentions a base64 header without assembling a download is
// not smuggling; the reassembly machinery is what makes it an attack.
func TestHTMLSmuggling_PayloadStringWithoutAssemblyIgnored(t *testing.T) {
	s := loadRepoYaraScanner(t)
	legit := []byte(`<html><body><pre>Sample PE prefix: TVqQAAMAAAAEAAAA (documentation only)</pre></body></html>`)
	if hasYaraRule(s.ScanBytes(legit), "html_smuggling_payload") {
		t.Error("html_smuggling_payload FP: matched documentation quoting a base64 header")
	}
}

// The suppression has to bite when rules are compiled, not only when a tier is
// downloaded: cluster installs already carry a Forge tier on disk, and it is
// only refreshed weekly.
func TestSuppressedForgeRuleNotCompiled(t *testing.T) {
	dir := t.TempDir()
	forge := "rule Unrelated_Keep { strings: $a = \"zzmarker\" condition: $a }\n" +
		"rule ELCEEF_HTML_Smuggling_A : T1027 FILE\n{\n\tstrings:\n\t\t$b = \"zzmarker\"\n\tcondition:\n\t\t$b\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "yara-forge-core.yar"), []byte(forge), 0600); err != nil {
		t.Fatalf("writing rules: %v", err)
	}
	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	matches := s.ScanBytes([]byte("zzmarker"))
	if hasYaraRule(matches, "ELCEEF_HTML_Smuggling_A") {
		t.Error("suppressed Forge rule was compiled and matched")
	}
	if !hasYaraRule(matches, "Unrelated_Keep") {
		t.Error("suppression removed an unrelated rule from the same file")
	}
}
