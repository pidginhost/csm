package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/platform"
)

// A removal loaded after a restart has no sequence, so the cursor that clears
// alert state skips it. The snapshot must still return it.
func TestRemovedFilesIncludesLoadedRemovals(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	useRemovedFilesClock(t, &now)
	_, restart := useRemovedFilesState(t)
	loaded := filepath.Join(t.TempDir(), "loaded.php")
	rememberRemovedFile(loaded, strings.Repeat("a", 64), 1, "quarantine")
	restart()

	if since, _ := RemovedFilesSince(0); len(since) != 0 {
		t.Fatalf("loaded removal reported as new: %+v", since)
	}
	got := RemovedFiles()
	if len(got) != 1 || got[0].Path != loaded || got[0].Action != "quarantine" {
		t.Fatalf("RemovedFiles() = %+v, want the loaded removal of %s", got, loaded)
	}

	rememberRemovedFile(filepath.Join(t.TempDir(), "fresh.php"), strings.Repeat("b", 64), 2, "clean")
	if got := RemovedFiles(); len(got) != 2 {
		t.Fatalf("RemovedFiles() = %+v, want 2 removals", got)
	}

	now = now.Add(removedFileMemory)
	if got := RemovedFiles(); len(got) != 0 {
		t.Fatalf("expired removals still listed: %+v", got)
	}
}

func writeWebshellTestFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWebshellFlaggedFiles(t *testing.T) {
	home := t.TempDir()
	docroot := filepath.Join(home, "public_html")
	shop := filepath.Join(docroot, "shop")
	docroots := []string{docroot, shop}
	// The main site is a WordPress install; the upload directory is not.
	writeWebshellTestFile(t, filepath.Join(docroot, "wp-includes", "version.php"))

	listed := filepath.Join(docroot, "wp-includes", "listed.php")
	planted := filepath.Join(docroot, "wp-includes", "Text", "planted.php")
	stubPackageListing(t, func(path string) (bool, bool) {
		switch path {
		case listed:
			return true, true
		case planted:
			return false, true
		}
		return false, false
	})

	critical := func(check, path string) alert.Finding {
		return alert.Finding{Check: check, Severity: alert.Critical, FilePath: path}
	}
	deep := filepath.Join(docroot, "wp-content", "uploads", "x", "index.php")
	rebuilt := filepath.Join(docroot, "rebuilt.php")
	writeWebshellTestFile(t, rebuilt)
	gone := filepath.Join(docroot, "gone.php")

	tests := []struct {
		name    string
		latest  []alert.Finding
		removed []RemovedFile
		path    string
		want    bool
		removal bool
	}{
		{name: "critical malware finding", latest: []alert.Finding{critical("webshell", deep)}, path: deep, want: true},
		{name: "high severity", latest: []alert.Finding{{Check: "webshell", Severity: alert.High, FilePath: deep}}, path: deep},
		{name: "not a malware check", latest: []alert.Finding{critical("http_request_flood", deep)}, path: deep},
		{name: "not PHP-executable", latest: []alert.Finding{critical("webshell", filepath.Join(docroot, "a.jpg"))}, path: filepath.Join(docroot, "a.jpg")},
		{name: "outside every docroot", latest: []alert.Finding{critical("webshell", filepath.Join(home, "tmp", "a.php"))}, path: filepath.Join(home, "tmp", "a.php")},
		{name: "relative path", latest: []alert.Finding{critical("webshell", "public_html/a.php")}, path: "public_html/a.php"},
		{name: "docroot index", latest: []alert.Finding{critical("webshell", filepath.Join(docroot, "index.php"))}, path: filepath.Join(docroot, "index.php")},
		{name: "nested docroot index", latest: []alert.Finding{critical("webshell", filepath.Join(shop, "index.php"))}, path: filepath.Join(shop, "index.php")},
		{name: "file the release ships", latest: []alert.Finding{critical("webshell", listed)}, path: listed},
		{name: "planted at a core path", latest: []alert.Finding{critical("webshell", planted)}, path: planted, want: true},
		{name: "WordPress root entry file", latest: []alert.Finding{critical("webshell", filepath.Join(docroot, "wp-login.php"))}, path: filepath.Join(docroot, "wp-login.php")},
		{name: "entry file name outside a WordPress root", latest: []alert.Finding{critical("webshell", filepath.Join(docroot, "wp-content", "uploads", "wp-login.php"))}, path: filepath.Join(docroot, "wp-content", "uploads", "wp-login.php"), want: true},
		{name: "quarantined and still absent", removed: []RemovedFile{{Path: gone, Action: "quarantine"}}, path: gone, want: true, removal: true},
		{name: "quarantined path rebuilt clean", removed: []RemovedFile{{Path: rebuilt, Action: "quarantine"}}, path: rebuilt},
		{name: "quarantined path flagged again", latest: []alert.Finding{critical("webshell", rebuilt)}, removed: []RemovedFile{{Path: rebuilt, Action: "quarantine"}}, path: rebuilt, want: true},
		{name: "cleaned file", removed: []RemovedFile{{Path: gone, Action: "clean"}}, path: gone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := webshellFlaggedFiles(tt.latest, tt.removed, docroots)
			removal, ok := got[tt.path]
			if ok != tt.want || removal != tt.removal {
				t.Fatalf("flagged[%s] = (%v, %v), want (%v, %v); set %v", tt.path, removal, ok, tt.removal, tt.want, got)
			}
			if !tt.want && got != nil {
				t.Fatalf("nothing is flagged, want a nil set, got %v", got)
			}
		})
	}
}

func TestRequestedFile(t *testing.T) {
	const docroot = "/home/alice/public_html"
	const shell = docroot + "/x/shell.php"
	const index = docroot + "/a/b/index.php"
	flagged := map[string]bool{index: false, shell: true}

	tests := []struct {
		uri  string
		want string
	}{
		{"/x/shell.php", shell},
		{"/x/shell.php?cmd=id", shell},
		{"/x/shell.php#frag", shell},
		{"/x/shell.php/anything/else", shell},
		{"/x//shell.php", shell},
		{"/x/./y/../shell.php", shell},
		{"/x/%73hell.php", shell},
		{"/x/shell%2Ephp", shell},
		{"/x/%2573hell.php", ""},
		{"/a/b/", index},
		{"/a/b/?x=1", index},
		{"/a/b", ""},
		{"/a/b/index.php", index},
		{"/", ""},
		{"", ""},
		{"/../../etc/passwd", ""},
		{"/x/shell.php%00.jpg", ""},
		{"/x/%zz", ""},
		{"http://example.com/x/shell.php", ""},
		{"/x/SHELL.PHP", ""},
		{"/other/shell.php", ""},
		{"/x/shell.phpx", ""},
	}
	for _, tt := range tests {
		got, ok := requestedFile(docroot, tt.uri, flagged)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("requestedFile(%q) = (%q, %v), want %q", tt.uri, got, ok, tt.want)
		}
	}
}

const (
	callerDocroot = "/home/alice/public_html"
	callerShell   = callerDocroot + "/x/shell.php"
)

func callerLine(ip string, at time.Time, method, uri string, status int) string {
	return ip + ` - - [` + at.Format("02/Jan/2006:15:04:05 -0700") + `] "` + method + ` ` + uri + ` HTTP/1.1" ` + itoa(status) + ` 100 "-" "Mozilla/5.0"`
}

type callerRequest struct {
	domain, account, line string
}

// scanCallers feeds requests through the domlog aggregator with callers
// loaded, as the domlog pass does for per-vhost logs.
func scanCallers(t *testing.T, cfg *config.Config, bot botClassifier, callers *webshellCallers, requests ...callerRequest) []alert.Finding {
	t.Helper()
	stats := newDomlogStatsAt(domlogScanTime)
	stats.callers = callers
	for _, r := range requests {
		rec, ok := parseAccessLogRecord(r.line)
		if !ok {
			t.Fatalf("unparsed line %q", r.line)
		}
		rec.Domain, rec.Account = r.domain, r.account
		stats.scan(rec, cfg, bot)
	}
	var out []alert.Finding
	for _, f := range stats.emit(cfg) {
		if f.Check == "webshell_caller" || f.Check == "webshell_path_public" {
			out = append(out, f)
		}
	}
	return out
}

func aliceCallers(flagged map[string]bool) *webshellCallers {
	return &webshellCallers{
		docroots: map[string]string{
			"example.com":       callerDocroot,
			"shop.example.com":  callerDocroot + "/shop",
			"other.example.com": "/home/bob/public_html",
		},
		flagged: flagged,
	}
}

func aliceRequest(ip string, second int, method, uri string, status int) callerRequest {
	return callerRequest{"example.com", "alice", callerLine(ip, domlogScanTime.Add(time.Duration(second-60)*time.Second), method, uri, status)}
}

func TestWebshellCallerReported(t *testing.T) {
	const ip = "192.0.2.10"
	findings := scanCallers(t, &config.Config{}, nopBotClassifier{}, aliceCallers(map[string]bool{callerShell: false}),
		aliceRequest(ip, 1, "POST", "/x/shell.php", 200),
		aliceRequest(ip, 2, "POST", "/x/shell.php?a=1", 200),
		aliceRequest(ip, 3, "GET", "/x/shell.php", 200),
		aliceRequest(ip, 4, "POST", "/x/shell.php/info", 200),
		aliceRequest(ip, 5, "GET", "/", 200))
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one caller", findings)
	}
	f := findings[0]
	if f.Check != "webshell_caller" || f.Severity != alert.High || f.SourceIP != ip || f.TenantID != "alice" || f.Domain != "example.com" || f.FilePath != "" {
		t.Fatalf("finding = %+v", f)
	}
	for _, want := range []string{"4 requests", "3 POST", callerShell, "POST /x/shell.php/info 200"} {
		if !strings.Contains(f.Details, want) {
			t.Errorf("details %q lack %q", f.Details, want)
		}
	}
	if strings.Contains(f.Details, "(removed)") {
		t.Errorf("details %q call a present file removed", f.Details)
	}
	for _, check := range []string{"webshell_caller", "webshell_path_public"} {
		if got := ResponsePolicyFor(check); got != (ResponsePolicy{}) {
			t.Errorf("%s has a response policy: %+v", check, got)
		}
		if _, ok := LookupCheck(check); !ok {
			t.Errorf("%s is not registered", check)
		}
	}
}

func TestWebshellCallerOtherSiteNotCounted(t *testing.T) {
	findings := scanCallers(t, &config.Config{}, nopBotClassifier{}, aliceCallers(map[string]bool{callerShell: false}),
		callerRequest{"other.example.com", "bob", callerLine("192.0.2.10", domlogScanTime.Add(-time.Minute), "POST", "/x/shell.php", 200)},
		callerRequest{"unknown.example.com", "", callerLine("192.0.2.10", domlogScanTime.Add(-time.Minute), "POST", "/x/shell.php", 200)},
		callerRequest{"", "", callerLine("192.0.2.10", domlogScanTime.Add(-time.Minute), "POST", "/x/shell.php", 200)})
	if len(findings) != 0 {
		t.Fatalf("a request on another site was counted: %+v", findings)
	}
}

// An addon domain's document root can sit inside the main one: the file is
// then reachable under both sites, by different request paths.
func TestWebshellCallerNestedDocroot(t *testing.T) {
	nested := callerDocroot + "/shop/x/shell.php"
	findings := scanCallers(t, &config.Config{}, nopBotClassifier{}, aliceCallers(map[string]bool{nested: false}),
		aliceRequest("192.0.2.10", 1, "POST", "/shop/x/shell.php", 200),
		callerRequest{"shop.example.com", "alice", callerLine("192.0.2.11", domlogScanTime.Add(-time.Minute), "POST", "/x/shell.php", 200)},
		aliceRequest("192.0.2.12", 2, "POST", "/x/shell.php", 404))
	got := map[string]bool{}
	for _, f := range findings {
		got[f.SourceIP] = true
	}
	if len(findings) != 2 || !got["192.0.2.10"] || !got["192.0.2.11"] {
		t.Fatalf("findings = %+v, want one caller per site spelling", findings)
	}
}

func TestWebshellCallerRemovedPath404(t *testing.T) {
	findings := scanCallers(t, &config.Config{}, nopBotClassifier{}, aliceCallers(map[string]bool{callerShell: true}),
		aliceRequest("192.0.2.10", 1, "POST", "/x/shell.php", 404))
	if len(findings) != 1 || !strings.Contains(findings[0].Details, callerShell+" (removed)") {
		t.Fatalf("findings = %+v, want a caller of the removed file", findings)
	}
}

func TestWebshellCallerForwardedClient(t *testing.T) {
	cfg := &config.Config{}
	cfg.WebServer.TrustedProxies = []string{"203.0.113.80"}
	line := callerLine("203.0.113.80", domlogScanTime.Add(-time.Minute), "POST", "/x/shell.php", 200) + ` "192.0.2.44"`
	findings := scanCallers(t, cfg, nopBotClassifier{}, aliceCallers(map[string]bool{callerShell: false}),
		callerRequest{"example.com", "alice", line})
	if len(findings) != 1 || findings[0].SourceIP != "192.0.2.44" {
		t.Fatalf("findings = %+v, want the forwarded client", findings)
	}
}

func TestWebshellCallerSkipsInfraAndVerifiedBots(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"192.0.2.10"}}
	callers := aliceCallers(map[string]bool{callerShell: false})
	if got := scanCallers(t, cfg, nopBotClassifier{}, callers, aliceRequest("192.0.2.10", 1, "POST", "/x/shell.php", 200)); len(got) != 0 {
		t.Fatalf("infra address reported: %+v", got)
	}
	if got := scanCallers(t, &config.Config{}, verifiedBotClassifier{}, aliceCallers(map[string]bool{callerShell: false}), aliceRequest("192.0.2.11", 1, "GET", "/x/shell.php", 200)); len(got) != 0 {
		t.Fatalf("verified bot reported: %+v", got)
	}
}

// A quiet site's log tail can hold lines that are days old. They must not
// keep a caller reported forever.
func TestWebshellCallerLookback(t *testing.T) {
	at := func(age time.Duration) callerRequest {
		return callerRequest{"example.com", "alice", callerLine("192.0.2.10", domlogScanTime.Add(-age), "POST", "/x/shell.php", 200)}
	}
	if got := scanCallers(t, &config.Config{}, nopBotClassifier{}, aliceCallers(map[string]bool{callerShell: false}), at(25*time.Hour)); len(got) != 0 {
		t.Fatalf("a request older than the lookback was reported: %+v", got)
	}
	if got := scanCallers(t, &config.Config{}, nopBotClassifier{}, aliceCallers(map[string]bool{callerShell: false}), at(23*time.Hour)); len(got) != 1 {
		t.Fatalf("a request inside the lookback was not reported: %+v", got)
	}
	undated := callerRequest{"example.com", "alice", `192.0.2.10 - - [not a time] "POST /x/shell.php HTTP/1.1" 200 100 "-" "Mozilla/5.0"`}
	if got := scanCallers(t, &config.Config{}, nopBotClassifier{}, aliceCallers(map[string]bool{callerShell: false}), undated); len(got) != 0 {
		t.Fatalf("an undated request was reported: %+v", got)
	}
}

func TestWebshellCallerStableKey(t *testing.T) {
	scan := func(n int) alert.Finding {
		var requests []callerRequest
		for i := 0; i < n; i++ {
			requests = append(requests, aliceRequest("192.0.2.10", i, "POST", "/x/shell.php", 200))
		}
		got := scanCallers(t, &config.Config{}, nopBotClassifier{}, aliceCallers(map[string]bool{callerShell: false}), requests...)
		if len(got) != 1 {
			t.Fatalf("findings = %+v", got)
		}
		return got[0]
	}
	first, second := scan(1), scan(7)
	if first.Details == second.Details {
		t.Fatal("the two scans must differ in details for this test to mean anything")
	}
	if first.Key() != second.Key() || first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("identity changed with the request count: %q/%q vs %q/%q", first.Key(), first.Fingerprint(), second.Key(), second.Fingerprint())
	}
}

func publicRequests(clients int, uri string) []callerRequest {
	var out []callerRequest
	for i := 0; i < clients; i++ {
		out = append(out, aliceRequest("198.51.100."+itoa(i+1), i, "GET", uri, 200))
	}
	return out
}

func TestWebshellPathPublic(t *testing.T) {
	findings := scanCallers(t, &config.Config{}, nopBotClassifier{}, aliceCallers(map[string]bool{callerShell: false}), publicRequests(webshellPublicClients, "/x/shell.php")...)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want only the public path", findings)
	}
	f := findings[0]
	if f.Check != "webshell_path_public" || f.Severity != alert.Warning || f.SourceIP != "" || f.TenantID != "alice" || !strings.Contains(f.Message, callerShell) {
		t.Fatalf("finding = %+v", f)
	}
	if !strings.Contains(f.Details, itoa(webshellPublicClients)+" clients") {
		t.Errorf("details %q lack the client count", f.Details)
	}

	findings = scanCallers(t, &config.Config{}, nopBotClassifier{}, aliceCallers(map[string]bool{callerShell: false}), publicRequests(webshellPublicClients-1, "/x/shell.php")...)
	if len(findings) != webshellPublicClients-1 {
		t.Fatalf("%d findings below the public count, want one caller per client: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Check != "webshell_caller" {
			t.Fatalf("finding below the public count = %+v", f)
		}
	}
}

func TestWebshellCallerPublicPathDoesNotHideOtherPath(t *testing.T) {
	other := callerDocroot + "/y/other.php"
	requests := append(publicRequests(webshellPublicClients, "/x/shell.php"), aliceRequest("198.51.100.1", 30, "POST", "/y/other.php", 200))
	findings := scanCallers(t, &config.Config{}, nopBotClassifier{}, aliceCallers(map[string]bool{callerShell: false, other: false}), requests...)
	var callers []alert.Finding
	for _, f := range findings {
		if f.Check == "webshell_caller" {
			callers = append(callers, f)
		}
	}
	if len(findings) != 2 || len(callers) != 1 {
		t.Fatalf("findings = %+v, want the public path and one caller", findings)
	}
	c := callers[0]
	if c.SourceIP != "198.51.100.1" || !strings.Contains(c.Details, other) || strings.Contains(c.Details, callerShell) || !strings.Contains(c.Details, "1 request") {
		t.Fatalf("caller = %+v, want only the non-public path", c)
	}
}

func TestWebshellCallersNilIsInert(t *testing.T) {
	if got := scanCallers(t, &config.Config{}, nopBotClassifier{}, nil, aliceRequest("192.0.2.10", 1, "POST", "/x/shell.php", 200)); len(got) != 0 {
		t.Fatalf("findings without a flagged set: %+v", got)
	}
}

func TestLoadWebshellCallers(t *testing.T) {
	if loadWebshellCallers(nil) != nil {
		t.Fatal("callers loaded without a store")
	}
	home := t.TempDir()
	docroot := filepath.Join(home, "public_html")
	shell := filepath.Join(docroot, "x", "shell.php")
	userdata := filepath.Join(t.TempDir(), "userdatadomains")
	if err := os.WriteFile(userdata, []byte("example.com: alice==root==main==example.com=="+docroot+"==192.0.2.1:80==192.0.2.1:443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(SetUserdataDomainsPathForTest(userdata))
	store := newTestStore(t)
	store.SetLatestFindings([]alert.Finding{{Check: "webshell", Severity: alert.Critical, FilePath: shell, Message: "webshell"}})

	setCallerPanel(t, platform.PanelNone)
	if loadWebshellCallers(store) != nil {
		t.Fatal("callers loaded on a host without cPanel")
	}
	setCallerPanel(t, platform.PanelCPanel)
	callers := loadWebshellCallers(store)
	if callers == nil || callers.docroots["example.com"] != docroot || len(callers.flagged) != 1 {
		t.Fatalf("callers = %+v, want the flagged shell under example.com", callers)
	}
	if removed, ok := callers.flagged[shell]; !ok || removed {
		t.Fatalf("flagged = %v", callers.flagged)
	}

	store.ClearLatestFindings()
	if loadWebshellCallers(store) != nil {
		t.Fatal("callers loaded with nothing flagged")
	}
}

func setCallerPanel(t *testing.T, panel platform.Panel) {
	t.Helper()
	platform.ResetForTest()
	platform.SetOverrides(platform.Overrides{Panel: &panel})
	t.Cleanup(platform.ResetForTest)
}

func TestRequestedFileNormalization(t *testing.T) {
	flagged := map[string]bool{callerShell: false, callerDocroot + "/a/b/index.php": false}
	for _, tt := range []struct{ uri, want string }{
		{"/../x/shell.php", ""},
		{"/a/../../x/shell.php", ""},
		{"/%2e%2e/x/shell.php", ""},
		{"/x%2fshell.php", ""},
		{"/x%2Fshell.php", ""},
		{"/a/b/.", callerDocroot + "/a/b/index.php"},
		{"/a/b/c/..", callerDocroot + "/a/b/index.php"},
		{"/a/b/%2e", callerDocroot + "/a/b/index.php"},
	} {
		got, ok := requestedFile(callerDocroot, tt.uri, flagged)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("%q: got (%q, %v), want %q", tt.uri, got, ok, tt.want)
		}
	}
}

func TestWebshellCallerKeepsRequestDomain(t *testing.T) {
	nested := callerDocroot + "/shop/x/shell.php"
	for _, sameClient := range []bool{false, true} {
		secondIP := "192.0.2.11"
		if sameClient {
			secondIP = "192.0.2.10"
		}
		requests := []callerRequest{
			aliceRequest("192.0.2.10", 1, "GET", "/shop/x/shell.php", 200),
			{"shop.example.com", "alice", callerLine(secondIP, domlogScanTime.Add(-time.Minute), "GET", "/x/shell.php", 200)},
		}
		for _, reverse := range []bool{false, true} {
			if reverse {
				requests[0], requests[1] = requests[1], requests[0]
			}
			got := scanCallers(t, &config.Config{}, nopBotClassifier{}, aliceCallers(map[string]bool{nested: false}), requests...)
			if sameClient {
				if len(got) != 1 || got[0].Domain != "" || !strings.Contains(got[0].Details, "2 requests") || strings.Count(got[0].Details, nested) != 1 {
					t.Fatalf("shared caller: %+v", got)
				}
			} else {
				if len(got) != 2 {
					t.Fatalf("callers: %+v", got)
				}
				for _, f := range got {
					want := "example.com"
					if f.SourceIP == secondIP {
						want = "shop.example.com"
					}
					if f.Domain != want {
						t.Errorf("caller %s: domain %q, want %q", f.SourceIP, f.Domain, want)
					}
				}
			}
		}
	}
}

func TestWebshellPublicCountsExcludedClients(t *testing.T) {
	requests := publicRequests(webshellPublicClients, "/x/shell.php")
	cfg := &config.Config{}
	for i := 1; i < webshellPublicClients; i++ {
		cfg.InfraIPs = append(cfg.InfraIPs, "198.51.100."+itoa(i))
	}
	got := scanCallers(t, cfg, nopBotClassifier{}, aliceCallers(map[string]bool{callerShell: false}), requests...)
	if len(got) != 1 || got[0].Check != "webshell_path_public" {
		t.Fatalf("public clients reported individually: %+v", got)
	}
}

func TestWebshellCallerFullRequestTarget(t *testing.T) {
	// Truncation leaves a shell prefix; the complete URI resolves elsewhere.
	prefix := "/x/shell.php/" + strings.Repeat("a/", 2100)
	requests := []callerRequest{
		aliceRequest("192.0.2.10", 1, "GET", prefix+strings.Repeat("../", 2101)+"safe.php", 200),
		aliceRequest("192.0.2.11", 2, "GET", "/"+strings.Repeat("./", 2100)+"x/shell.php", 200),
	}
	logPath := filepath.Join(t.TempDir(), "example.com")
	if err := os.WriteFile(logPath, []byte(requests[0].line+"\n"+requests[1].line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stats := newDomlogStatsAt(domlogScanTime)
	stats.callers = aliceCallers(map[string]bool{callerShell: false})
	if n := tailDomlogsInto(context.Background(), []string{logPath}, &config.Config{}, stats, nopBotClassifier{}, 10); n != 1 {
		t.Fatalf("scanned %d logs", n)
	}
	got := stats.callers.emit()
	if len(got) != 1 || got[0].SourceIP != "192.0.2.11" {
		t.Fatalf("truncated target used: %+v", got)
	}
}

// Publicness counts addresses across aliases, not address/domain pairs.
func TestWebshellPublicAliasesCountDistinctClients(t *testing.T) {
	for _, count := range []int{webshellPublicClients - 1, webshellPublicClients} {
		callers := aliceCallers(map[string]bool{callerShell: false})
		callers.docroots["shop.example.com"] = callerDocroot
		var requests []callerRequest
		for _, request := range publicRequests(count, "/x/shell.php") {
			requests = append(requests, request)
			request.domain = "shop.example.com"
			requests = append(requests, request)
		}
		got := scanCallers(t, &config.Config{}, nopBotClassifier{}, callers, requests...)
		if count == webshellPublicClients {
			if len(got) != 1 || got[0].Check != "webshell_path_public" || got[0].Domain != "" || got[0].TenantID != "alice" || !strings.Contains(got[0].Details, itoa(count)+" clients") {
				t.Fatalf("public aliases: %+v", got)
			}
		} else {
			if len(got) != count {
				t.Fatalf("alias visitors: %+v", got)
			}
			for _, f := range got {
				if f.Check != "webshell_caller" || f.Domain != "" || !strings.Contains(f.Details, "2 requests") {
					t.Fatalf("alias visitor: %+v", f)
				}
			}
		}
	}
}

func TestWebshellPublicCountsVerifiedBots(t *testing.T) {
	got := scanCallers(t, &config.Config{}, verifiedBotClassifier{}, aliceCallers(map[string]bool{callerShell: false}), publicRequests(webshellPublicClients, "/x/shell.php")...)
	if len(got) != 1 || got[0].Check != "webshell_path_public" || got[0].SourceIP != "" {
		t.Fatalf("public bot requests: %+v", got)
	}
}
