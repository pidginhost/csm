package checks

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
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

func TestIsRealPHPInfoBodyRecognizesUTF16Banner(t *testing.T) {
	encodeASCII := func(s string, littleEndian bool) []byte {
		out := make([]byte, len(s)*2)
		for i := range len(s) {
			if littleEndian {
				out[i*2] = s[i]
			} else {
				out[i*2+1] = s[i]
			}
		}
		return out
	}
	text := strings.Repeat("directive=value\n", 300) + "PHP Version 8.2.20"
	for _, littleEndian := range []bool{true, false} {
		if body := encodeASCII(text, littleEndian); !isRealPHPInfoBody(body) {
			t.Errorf("UTF-16 phpinfo banner not recognized (little-endian=%v, len=%d)", littleEndian, len(body))
		}
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
		ctx, collector := withIncompleteCheckCollector(context.Background())
		if findings := scanVhostsForExposure(ctx, vhosts, nil); len(findings) != 0 {
			t.Errorf("stub phpinfo produced findings: %+v", findings)
		}
		if collector.contains("exposed_files") {
			t.Error("two completed stub responses must allow an earlier finding to clear")
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
		ctx, collector := withIncompleteCheckCollector(context.Background())
		if findings := scanVhostsForExposure(ctx, vhosts, nil); len(findings) != 0 {
			t.Errorf("unverifiable phpinfo must not be flagged, got %+v", findings)
		}
		if !collector.contains("exposed_files") {
			t.Error("body fetch failure must preserve findings from the prior completed scan")
		}
	})

	t.Run("dump on alternate protocol is flagged with its scheme", func(t *testing.T) {
		var schemes []string
		withFakePHPInfoBody(t, func(_ context.Context, scheme, _, _, _ string) ([]byte, bool) {
			schemes = append(schemes, scheme)
			if scheme == "http" {
				return []byte(realPHPInfoHTML()), true
			}
			return nil, true
		})
		findings := scanVhostsForExposure(context.Background(), vhosts, nil)
		if len(findings) != 1 || !strings.Contains(findings[0].Message, "http://alice.example.com/phpinfo.php") {
			t.Fatalf("expected HTTP phpinfo finding, got %+v", findings)
		}
		if got := strings.Join(schemes, ","); got != "https,http" {
			t.Fatalf("body fetch schemes = %q, want https,http", got)
		}
	})
}

func newExposureTestClient(t *testing.T, handler http.Handler) *http.Client {
	t.Helper()
	client, closeIdle := exposureProbeHTTPClient("phpinfo.example", "192.0.2.10")
	t.Cleanup(closeIdle)
	client.Transport = newHandlerHTTPTransport(handler)
	return client
}

func TestDoLocalProbeWithClientPreservesHeadFallback(t *testing.T) {
	var requests []string
	var requestHost string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+":"+r.Header.Get("Range"))
		requestHost = r.Host
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(http.StatusPartialContent)
	})
	client := newExposureTestClient(t, handler)

	pr, ok := doLocalProbeWithClient(context.Background(), client, "http", "phpinfo.example", "/phpinfo.php")
	if !ok || pr.scheme != "http" || pr.status != http.StatusPartialContent || pr.contentType != "application/gzip" {
		t.Fatalf("doLocalProbeWithClient() = (%+v, %v), want HTTP 206 gzip response", pr, ok)
	}
	gotRequests := strings.Join(requests, ",")
	gotHost := requestHost
	if gotRequests != "HEAD:,GET:bytes=0-0" {
		t.Fatalf("probe requests = %q, want HEAD then ranged GET", gotRequests)
	}
	if gotHost != "phpinfo.example" {
		t.Fatalf("request Host = %q, want phpinfo.example", gotHost)
	}
}

func TestDoLocalProbeWithClientStopsAfterSuccessfulHead(t *testing.T) {
	getCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getCalled = true
		}
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
	})
	client := newExposureTestClient(t, handler)

	pr, ok := doLocalProbeWithClient(context.Background(), client, "https", "phpinfo.example", "/phpinfo.php")
	if !ok || pr.scheme != "https" || pr.status != http.StatusOK || pr.contentType != "text/html; charset=UTF-8" {
		t.Fatalf("doLocalProbeWithClient() = (%+v, %v), want HTTPS 200 HTML response", pr, ok)
	}
	if getCalled {
		t.Fatal("successful HEAD unexpectedly fell back to GET")
	}
}

func TestExposureProbeHTTPClientPreservesProbeSettings(t *testing.T) {
	client, closeIdle := exposureProbeHTTPClient("phpinfo.example", "192.0.2.10")
	t.Cleanup(closeIdle)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport = %T, want *http.Transport", client.Transport)
	}
	if client.Timeout != exposureProbeTotalTimeout || transport.MaxResponseHeaderBytes != 64<<10 {
		t.Fatalf("client bounds = (%s, %d), want (%s, %d)", client.Timeout, transport.MaxResponseHeaderBytes, exposureProbeTotalTimeout, 64<<10)
	}
	if transport.DialContext == nil || transport.TLSClientConfig == nil ||
		!transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.ServerName != "phpinfo.example" {
		t.Fatalf("pinned transport settings changed: %+v", transport.TLSClientConfig)
	}
}

func TestExposureProbeClientDoesNotFollowRedirects(t *testing.T) {
	redirected := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			redirected = true
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	client := newExposureTestClient(t, handler)

	pr, ok := doLocalProbeWithClient(context.Background(), client, "http", "phpinfo.example", "/phpinfo.php")
	if !ok || pr.status != http.StatusFound {
		t.Fatalf("redirect probe = (%+v, %v), want reachable 302", pr, ok)
	}
	if redirected {
		t.Fatal("exposure probe followed a redirect")
	}
}

func TestFetchPHPInfoBodyWithClientDecodesGzipBody(t *testing.T) {
	want := []byte(realPHPInfoHTML())
	var requestHost string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestHost = r.Host
		w.Header().Set("Content-Type", "text/html; charset=ISO-8859-1")
		w.Header().Set("Content-Encoding", "gzip")
		var compressed bytes.Buffer
		zw := gzip.NewWriter(&compressed)
		_, _ = zw.Write(want)
		_ = zw.Close()
		_, _ = w.Write(compressed.Bytes())
	})
	client := newExposureTestClient(t, handler)

	body, complete := fetchPHPInfoBodyWithClient(context.Background(), client, "http://phpinfo.example/phpinfo.php")
	if !complete || !bytes.Equal(body, want) {
		t.Fatalf("gzip body fetch = (%d bytes, %v), want %d decoded bytes", len(body), complete, len(want))
	}
	if requestHost != "phpinfo.example" {
		t.Fatalf("request Host = %q, want phpinfo.example", requestHost)
	}
	if !isRealPHPInfoBody(body) {
		t.Fatal("decoded gzip phpinfo body was not recognized")
	}
}

func TestFetchPHPInfoBodyWithClientStatusAndBounds(t *testing.T) {
	t.Run("partial content is inspected", func(t *testing.T) {
		client := newHandlerHTTPClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = io.WriteString(w, realPHPInfoHTML())
		}))
		body, complete := fetchPHPInfoBodyWithClient(context.Background(), client, localHTTPTestURL)
		if !complete || !isRealPHPInfoBody(body) {
			t.Fatalf("partial body fetch = (%d bytes, %v), want confirmed dump", len(body), complete)
		}
	})

	t.Run("partial content without a dump is incomplete", func(t *testing.T) {
		client := newHandlerHTTPClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = io.WriteString(w, "stub")
		}))
		body, complete := fetchPHPInfoBodyWithClient(context.Background(), client, localHTTPTestURL)
		if complete || len(body) != 0 {
			t.Fatalf("partial stub fetch = (%d bytes, %v), want empty incomplete result", len(body), complete)
		}
	})

	t.Run("non-success status is a complete negative", func(t *testing.T) {
		client := newHandlerHTTPClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		body, complete := fetchPHPInfoBodyWithClient(context.Background(), client, localHTTPTestURL)
		if !complete || len(body) != 0 {
			t.Fatalf("404 body fetch = (%d bytes, %v), want empty complete result", len(body), complete)
		}
	})

	t.Run("transport failure is incomplete", func(t *testing.T) {
		body, complete := fetchPHPInfoBodyWithClient(context.Background(), newFailingHTTPClient("down"), localHTTPTestURL)
		if complete || len(body) != 0 {
			t.Fatalf("failed body fetch = (%d bytes, %v), want empty incomplete result", len(body), complete)
		}
	})

	t.Run("unsupported content encoding is incomplete", func(t *testing.T) {
		client := newHandlerHTTPClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "br")
			_, _ = io.WriteString(w, realPHPInfoHTML())
		}))
		body, complete := fetchPHPInfoBodyWithClient(context.Background(), client, localHTTPTestURL)
		if complete || len(body) != 0 {
			t.Fatalf("unsupported encoding fetch = (%d bytes, %v), want empty incomplete result", len(body), complete)
		}
	})

	t.Run("body read is bounded", func(t *testing.T) {
		client := newHandlerHTTPClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, strings.Repeat("x", phpinfoBodyReadMax+1024))
		}))
		body, complete := fetchPHPInfoBodyWithClient(context.Background(), client, localHTTPTestURL)
		if !complete || len(body) != phpinfoBodyReadMax {
			t.Fatalf("bounded body fetch = (%d bytes, %v), want %d complete bytes", len(body), complete, phpinfoBodyReadMax)
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
