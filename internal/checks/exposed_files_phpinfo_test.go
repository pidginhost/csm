package checks

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func withFakePHPInfoBody(t *testing.T, f phpinfoBodyFetcher) {
	t.Helper()
	prev := fetchPHPInfoBody
	fetchPHPInfoBody = f
	t.Cleanup(func() { fetchPHPInfoBody = prev })
}

func realPHPInfoHTML() string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html><html><head><title>PHP 8.2.20 - phpinfo()</title></head><body>")
	b.WriteString(`<h1 class="p">PHP Version 8.2.20</h1>`)
	for i := 0; i < 400; i++ {
		b.WriteString(`<tr><td class="e">some.directive</td><td class="v">enabled</td></tr>`)
	}
	b.WriteString("</body></html>")
	return b.String()
}

func TestIsRealPHPInfoBody(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"full phpinfo dump", realPHPInfoHTML(), true},
		{"cli-style text dump", "phpinfo()\nPHP Version => 8.2.20\n\n" + strings.Repeat("directive => value\n", 400), true},
		{"empty stub output", "", false},
		{"raw stub source served as text", "<?php phpinfo();", false},
		{"tiny html without marker", "<html><body>ok</body></html>", false},
		{"large page without phpinfo marker", "<html>" + strings.Repeat("<p>content</p>", 1000) + "</html>", false},
		{"marker present but body below minimum", "<h1>PHP Version 8.2.20</h1>", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRealPHPInfoBody([]byte(tc.body)); got != tc.want {
				t.Errorf("isRealPHPInfoBody(len=%d) = %v, want %v", len(tc.body), got, tc.want)
			}
		})
	}
}

// TestScanPHPInfoRequiresRealDump reproduces the production false positive:
// 19-27 byte phpinfo.php stubs answer 200 text/html but render no phpinfo
// output. Only a response carrying a real dump may produce a finding.
func TestScanPHPInfoRequiresRealDump(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, "alice", "public_html")
	mustWrite(t, filepath.Join(site, "phpinfo.php"), "<?php phpinfo();")
	vhosts := []vhost{{domain: "alice.example.com", user: "alice", typ: "main", docroot: site, ip: "192.0.2.10"}}

	withFakeProbe(t, &fakeProbe{byPath: map[string]probeResult{
		"/phpinfo.php": {status: 200, contentType: "text/html", reachable: true, scheme: "https"},
	}})

	t.Run("stub output is not flagged", func(t *testing.T) {
		withFakePHPInfoBody(t, func(_ context.Context, _, _, _, _ string) ([]byte, bool) {
			return nil, true
		})
		if findings := scanVhostsForExposure(context.Background(), vhosts, nil); len(findings) != 0 {
			t.Errorf("stub phpinfo produced findings: %+v", findings)
		}
	})

	t.Run("real dump is flagged", func(t *testing.T) {
		withFakePHPInfoBody(t, func(_ context.Context, _, _, _, _ string) ([]byte, bool) {
			return []byte(realPHPInfoHTML()), true
		})
		findings := scanVhostsForExposure(context.Background(), vhosts, nil)
		if len(findings) != 1 || findings[0].Check != "web_exposed_phpinfo" {
			t.Fatalf("expected one web_exposed_phpinfo finding, got %+v", findings)
		}
	})

	t.Run("body fetch failure fails closed", func(t *testing.T) {
		withFakePHPInfoBody(t, func(_ context.Context, _, _, _, _ string) ([]byte, bool) {
			return nil, false
		})
		if findings := scanVhostsForExposure(context.Background(), vhosts, nil); len(findings) != 0 {
			t.Errorf("unverifiable phpinfo must not be flagged, got %+v", findings)
		}
	})
}

// TestScanNonPHPInfoSkipsBodyFetch ensures the body confirmation stage stays
// scoped to the phpinfo class: raw-leak classes are confirmed by headers alone.
func TestScanNonPHPInfoSkipsBodyFetch(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, "alice", "public_html")
	mustWrite(t, filepath.Join(site, "softsql.sql"), "-- dump\n")
	vhosts := []vhost{{domain: "alice.example.com", user: "alice", typ: "main", docroot: site, ip: "192.0.2.10"}}

	withFakeProbe(t, &fakeProbe{byPath: map[string]probeResult{
		"/softsql.sql": {status: 200, contentType: "text/x-sql", reachable: true},
	}})
	called := false
	withFakePHPInfoBody(t, func(_ context.Context, _, _, _, _ string) ([]byte, bool) {
		called = true
		return nil, false
	})

	findings := scanVhostsForExposure(context.Background(), vhosts, nil)
	if len(findings) != 1 || findings[0].Check != "web_exposed_db_dump" {
		t.Fatalf("expected the db dump finding, got %+v", findings)
	}
	if called {
		t.Error("body fetch must not run for non-phpinfo classes")
	}
}
