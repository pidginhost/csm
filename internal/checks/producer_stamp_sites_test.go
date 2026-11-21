package checks

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/pidginhost/csm/internal/sourcewalk"
)

// stampSiteKey names the declaration an address-bearing finding is built
// in: its file and function, with the receiver type for a method. Lines
// move with every edit; the function a finding comes from does not.
func stampSiteKey(rel string, decl ast.Decl) string {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok {
		return filepath.ToSlash(rel[:strings.LastIndex(rel, ".go")+3]) + ":(package scope)"
	}
	name := fn.Name.Name
	if fn.Recv != nil && len(fn.Recv.List) == 1 {
		t := fn.Recv.List[0].Type
		if star, ok := t.(*ast.StarExpr); ok {
			t = star.X
		}
		if idx, ok := t.(*ast.IndexExpr); ok {
			t = idx.X
		}
		if id, ok := t.(*ast.Ident); ok {
			name = id.Name + "." + name
		}
	}
	return filepath.ToSlash(rel[:strings.LastIndex(rel, ".go")+3]) + ":" + name
}

// stampMechanisms names each way a producer stamps its findings with an
// observation, and the test that proves it does. An exemption says why a
// site's findings need no stamp.
var stampMechanisms = map[string]string{
	// A framed-line handler's findings are stamped by the watcher or the
	// line dispatcher that called it.
	"log watcher":  "TestLogWatcherStampsObservation,TestFixedLogSpecsNameTheirProducers,TestAccessLogWatchersNameTheirProducer,TestModSecWatcherNamesItsProducer,TestMailLogDispatchStampsObservation,TestDispatchLogLineStampsProducer",
	"pam listener": "TestPAMFailureCarriesItsObservation",
	// A journal source's dispatcher stamps the findings of entries its
	// service wrote.
	"journal reader": "TestSSHJournalLineParses,TestFTPJournalBruteforceBlocks,TestDispatchLogLineStampsProducer",
	// The realtime sshd reader and the follow scan stamp what this builder
	// returns; its store-less tail caller, like the FTP one, stamps nothing.
	"ssh login readers":   "TestSSHLoginScanStampsObservation,TestLogWatcherStampsObservation,TestFixedLogSpecsNameTheirProducers",
	"ftp scan":            "TestFTPBruteforceNamesItsNewestFailure",
	"cpanel scan":         "TestAPIAuthFailureScanNamesItsNewestFailure,TestWebmailScanNamesItsNewestAttempt",
	"domlog scan":         "TestDomlogScanNamesEachFindingsNewestRecord,TestDomlogForwardedFindingNamesItsChainWithoutARecord",
	"modsec audit scan":   "TestModSecAuditScanNamesItsNewestDenial",
	"reputation scan":     "TestReputationFindingNamesItsSighting,TestCachedReputationFindingNamesItsSighting",
	"connection scan":     "TestC2ConnectionStampsOutboundOnly,TestC2ConnectionStampsSocketObservation",
	"exim history scan":   "TestEximHistoryScanNamesItsNewestSend",
	"php relay spool":     "TestPath6_AdmissionRefusesTheHeaderAddress",
	"store-less fallback": "exempt: runs only without a state store; the daemon and every runner caller pass one",
	"asn crawl":           "exempt: a range finding; admission refuses ranges until range corroboration exists",
}

// stampSilentChecks lists published checks no production finding literal
// carries an address for, with where their address comes from.
var stampSilentChecks = map[string]string{}

// stampSites assigns every production function that builds a finding a
// registered producer publishes to its stamping mechanism.
var stampSites = map[string]string{
	"internal/checks/bruteforce.go:CheckAPIAuthFailures":                   "cpanel scan",
	"internal/checks/bruteforce.go:CheckWebmailLogins":                     "cpanel scan",
	"internal/checks/bruteforce.go:CheckFTPLogins":                         "ftp scan",
	"internal/checks/bruteforce.go:checkFTPLoginsLegacy":                   "store-less fallback",
	"internal/checks/http_abuse.go:domlogStats.emit":                       "domlog scan",
	"internal/checks/http_abuse.go:domlogStats.emitClaimedBotUnverified":   "domlog scan",
	"internal/checks/http_abuse.go:domlogStats.emitLegacy":                 "domlog scan",
	"internal/checks/http_abuse.go:domlogStats.emitScannerProfile":         "domlog scan",
	"internal/checks/http_abuse.go:domlogStats.makeUASpoofFinding":         "domlog scan",
	"internal/checks/http_asn_crawl.go:domlogStats.emitASNCrawl":           "asn crawl",
	"internal/checks/network.go:scanOutboundConnections":                   "connection scan",
	"internal/checks/reputation.go:CheckIPReputation":                      "reputation scan",
	"internal/checks/reputation.go:appendReputationFinding":                "reputation scan",
	"internal/checks/waf.go:CheckModSecAuditLog":                           "modsec audit scan",
	"internal/checks/whm.go:SSHAcceptedLoginFinding":                       "ssh login readers",
	"internal/daemon/cloud_relay.go:cloudRelayObserve":                     "log watcher",
	"internal/daemon/cloud_relay_scan.go:ScanEximHistoryForCloudRelay":     "exim history scan",
	"internal/daemon/handlers.go:parseAccessLogLineEnhanced":               "log watcher",
	"internal/daemon/handlers.go:parseFTPLogLine":                          "log watcher",
	"internal/daemon/handlers_accesslog.go:parseAccessLogBruteForceForLog": "log watcher",
	"internal/daemon/handlers_modsec.go:parseModSecLogLineDeduped":         "log watcher",
	"internal/daemon/journal_source.go:Daemon.handleFTPJournalLine":        "journal reader",
	"internal/daemon/mailbrute.go:mailAuthTracker.RecordResolvedObserved":  "log watcher",
	"internal/daemon/mailbrute.go:mailAuthTracker.recordSuccessAt":         "log watcher",
	"internal/daemon/mailspray_findings.go:sprayFinding":                   "log watcher",
	"internal/daemon/pam_listener.go:PAMListener.recordFailure":            "pam listener",
	"internal/daemon/php_relay.go:evaluator.formRelayFindings":             "php relay spool",
	"internal/daemon/smtpbrute.go:smtpAuthTracker.recordFailure":           "log watcher",
	"internal/daemon/smtpprobe.go:smtpProbeTracker.Record":                 "log watcher",
	"internal/daemon/stalwart_auth.go:Daemon.stalwartBan":                  "log watcher",
}

// TestPublishedFindingsNameTheirStamp walks every production finding that
// carries an address under a check a registered producer publishes. Each
// building function must name the mechanism that stamps it, so a new path
// that would reach admission without an observation fails here first.
func TestPublishedFindingsNameTheirStamp(t *testing.T) {
	published := map[string]bool{}
	for _, p := range ProducerTable() {
		for _, check := range p.Spec.Checks {
			published[check] = true
		}
	}
	producers, unresolved, _ := scanAddressProducersReviewed(t, findRepoRoot(t), reviewedEvidenceRestores)
	if len(unresolved) != 0 {
		t.Fatalf("unresolved address producers: %v", unresolved)
	}
	sites := map[string][]string{}
	for _, p := range producers {
		for _, check := range p.checks {
			if published[check] && !slices.Contains(sites[p.fn], check) {
				sites[p.fn] = append(sites[p.fn], check)
			}
		}
	}
	covered := map[string]bool{}
	for _, checks := range sites {
		for _, check := range checks {
			covered[check] = true
		}
	}
	var silent []string
	for check := range published {
		if !covered[check] && strings.TrimSpace(stampSilentChecks[check]) == "" {
			silent = append(silent, check)
		}
	}
	sort.Strings(silent)
	for _, check := range silent {
		t.Errorf("published check %s has no address-bearing finding site: list it in stampSilentChecks with the reason", check)
	}
	for check := range stampSilentChecks {
		if !published[check] || covered[check] {
			t.Errorf("stampSilentChecks lists %s, which is unpublished or has a site", check)
		}
	}
	var missing []string
	for site, checks := range sites {
		if _, ok := stampSites[site]; !ok {
			sort.Strings(checks)
			missing = append(missing, site+" "+strings.Join(checks, ","))
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("unreviewed stamping site: %s", m)
	}
	used := map[string]bool{}
	for site, mechanism := range stampSites {
		if _, ok := sites[site]; !ok {
			t.Errorf("stampSites lists %s, which builds no published finding", site)
		}
		if _, ok := stampMechanisms[mechanism]; !ok {
			t.Errorf("%s names unknown mechanism %q", site, mechanism)
		}
		used[mechanism] = true
	}
	tests := testFunctionNames(t, findRepoRoot(t))
	for mechanism, proof := range stampMechanisms {
		if !used[mechanism] {
			t.Errorf("mechanism %q stamps no site", mechanism)
		}
		if strings.HasPrefix(proof, "exempt: ") {
			if strings.TrimSpace(strings.TrimPrefix(proof, "exempt: ")) == "" {
				t.Errorf("mechanism %q has no exemption reason", mechanism)
			}
			continue
		}
		for _, name := range strings.Split(proof, ",") {
			if !tests[strings.TrimSpace(name)] {
				t.Errorf("mechanism %q names %q, which is not a test", mechanism, name)
			}
		}
	}
}

// testFunctionNames inventories all build variants, as the producer walk
// does, but ignores fixtures and helpers that go test would never run.
func testFunctionNames(t *testing.T, root string) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, top := range []string{"internal", "cmd"} {
		dir := filepath.Join(root, top)
		err := filepath.WalkDir(dir, sourcewalk.IgnoreVanished(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			ignored := strings.HasPrefix(d.Name(), ".") || strings.HasPrefix(d.Name(), "_")
			if d.IsDir() {
				if ignored || d.Name() == "testdata" || d.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if ignored || !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			for _, decl := range f.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && isStampProofTest(f, fn) {
					names[fn.Name.Name] = true
				}
			}
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
	}
	return names
}

func isStampProofTest(file *ast.File, fn *ast.FuncDecl) bool {
	if fn.Recv != nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") ||
		fn.Type.TypeParams.NumFields() != 0 || fn.Type.Params.NumFields() != 1 || fn.Type.Results.NumFields() != 0 {
		return false
	}
	if suffix := strings.TrimPrefix(fn.Name.Name, "Test"); suffix != "" {
		r, _ := utf8.DecodeRuneInString(suffix)
		if unicode.IsLower(r) {
			return false
		}
	}
	arg, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != "testing" {
			continue
		}
		alias := "testing"
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		if id, ok := arg.X.(*ast.Ident); ok && alias == "." {
			return id.Name == "T"
		}
		if sel, ok := arg.X.(*ast.SelectorExpr); ok {
			pkg, ok := sel.X.(*ast.Ident)
			return ok && pkg.Name == alias && sel.Sel.Name == "T"
		}
	}
	return false
}
