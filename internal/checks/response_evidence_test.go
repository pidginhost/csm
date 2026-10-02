package checks

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
)

// evidencePolicy is the reviewed evidence family and basis of every check
// that can drive an automatic response. A check absent here has
// FamilyNone. Change it only with a reviewed policy decision.
var evidencePolicy = map[string]admission.Policy{
	"admin_panel_bruteforce":      {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"http_asn_crawl":              {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"http_claimed_bot_unverified": {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"http_request_flood":          {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"http_scanner_profile":        {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"http_ua_spoof":               {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"modsec_block_escalation":     {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"modsec_csm_block_escalation": {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"waf_attack_blocked":          {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"wp_login_bruteforce":         {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"wp_user_enumeration":         {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"xmlrpc_abuse":                {Family: admission.FamilyHTTP, Basis: admission.BasisLocal},
	"api_auth_failure":            {Family: admission.FamilyPanel, Basis: admission.BasisLocal},
	"api_auth_failure_realtime":   {Family: admission.FamilyPanel, Basis: admission.BasisLocal},
	"cpanel_multi_ip_login":       {Family: admission.FamilyPanel, Basis: admission.BasisLocal},
	"webmail_bruteforce":          {Family: admission.FamilyPanel, Basis: admission.BasisLocal},
	"email_cloud_relay_abuse":     {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"email_compromised_account":   {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"mail_bruteforce":             {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"mail_subnet_spray":           {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"smtp_bruteforce":             {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"smtp_probe_abuse":            {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"smtp_subnet_spray":           {Family: admission.FamilyMail, Basis: admission.BasisLocal},
	"credential_stuffing":         {Family: admission.FamilySSH, Basis: admission.BasisLocal},
	"pam_bruteforce":              {Family: admission.FamilySSH, Basis: admission.BasisLocal},
	"ssh_login_unknown_ip":        {Family: admission.FamilySSH, Basis: admission.BasisLocal},
	"ftp_auth_failure_realtime":   {Family: admission.FamilyFTP, Basis: admission.BasisLocal},
	"ftp_bruteforce":              {Family: admission.FamilyFTP, Basis: admission.BasisLocal},
	"ip_reputation":               {Family: admission.FamilyReputation, Basis: admission.BasisIntel},
	"local_threat_score":          {Family: admission.FamilyDerived, Basis: admission.BasisIntel},
	"c2_connection":               {Family: admission.FamilyNetwork, Basis: admission.BasisCompromise},
	"mail_account_compromised":    {Family: admission.FamilyMail, Basis: admission.BasisCompromise},
}

// reviewedCompromise is every check whose own evidence is C3. Each is
// direct evidence of successful unauthorized access or a compromised host,
// not a Critical label or an ordinary successful login.
var reviewedCompromise = map[string]string{
	"c2_connection":            "a local process holds a connection to a listed command-and-control address",
	"mail_account_compromised": "a login succeeded from the address after its brute force (Critical only)",
}

// notAddressEvidence lists checks whose producers carry an address that is
// never admissible attacker evidence, with the reason. Every other check
// with a structured address producer must be in evidencePolicy.
var notAddressEvidence = map[string]string{
	"auto_block":                   "record of a response already taken",
	"backdoor_port":                "peer of a local backdoor listener; contained by the process response, no address policy",
	"backdoor_port_outbound":       "destination address of an outbound connection",
	"bad_asn_outbound":             "destination address of an outbound connection",
	"cpanel_file_upload_realtime":  "authenticated customer activity",
	"cpanel_login":                 "authenticated customer login",
	"cpanel_login_realtime":        "authenticated customer login",
	"email_auth_failure_realtime":  "one raw mailbox failure; thresholded checks carry the evidence",
	"email_php_relay_abuse":        "visitor of a sending script, not necessarily the abuser",
	"email_suspicious_geo":         "mailbox owner login from a new country",
	"ftp_login":                    "authenticated customer login",
	"ftp_login_after_bruteforce":   "no response policy; candidate for a reviewed compromise decision",
	"mail_account_spray":           "most recent of many sources of a per-mailbox summary",
	"mail_bruteforce_suspected":    "advisory for an established source",
	"modsec_block_realtime":        "ModSecurity already denied the request",
	"modsec_classifier_gap":        "record of CSM's own rule classification coverage",
	"modsec_low_confidence_burst":  "low-confidence advisory",
	"modsec_warning_realtime":      "warning-level WAF event",
	"pam_login":                    "authenticated login",
	"password_hijack_confirmed":    "no response policy; candidate for a reviewed compromise decision",
	"php_shield_block":             "HTTP client of a shielded script; may be an ordinary visitor",
	"php_shield_eval":              "HTTP client of a shielded script; may be an ordinary visitor",
	"php_shield_webshell":          "HTTP client of a shielded script; may be an ordinary visitor",
	"smtp_account_spray":           "most recent of many sources of a per-mailbox summary",
	"webmail_login_realtime":       "authenticated customer login",
	"whm_login_realtime":           "authenticated login",
	"whm_password_change_noninfra": "no response policy; candidate for a reviewed compromise decision",
	"whm_unauth_scripts_realtime":  "unauthenticated WHM script probe; visibility only",
}

// respondingWithoutAddress are checks with a response policy whose
// producers carry no structured address today. Admission never parses
// message text, so these cannot produce evidence until a producer carries
// the address. The set is pinned so a change is reviewed.
var respondingWithoutAddress = []string{
	"cpanel_multi_ip_login",
	"email_compromised_account",
}

func TestRegistryEvidenceMatchesReviewedTable(t *testing.T) {
	for _, c := range checkRegistry {
		want := evidencePolicy[c.Name]
		if got := (admission.Policy{Family: c.Response.Evidence, Basis: c.Response.Basis}); got != want {
			t.Errorf("%q evidence = %s/%s, want %s/%s", c.Name, got.Family, got.Basis, want.Family, want.Basis)
		}
	}
	for name := range evidencePolicy {
		if _, ok := LookupCheck(name); !ok {
			t.Errorf("evidencePolicy lists unregistered check %q", name)
		}
	}
}

func TestReviewedCompromiseChecksAreExact(t *testing.T) {
	for _, c := range checkRegistry {
		_, reviewed := reviewedCompromise[c.Name]
		if (c.Response.Basis == admission.BasisCompromise) != reviewed {
			t.Errorf("%q has basis %s; reviewed compromise list says %v", c.Name, c.Response.Basis, reviewed)
		}
	}
	for name, reason := range reviewedCompromise {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("reviewed compromise check %q has no reason", name)
		}
	}
}

func TestValidateResponsePolicyRejectsEvidenceContradictions(t *testing.T) {
	cases := map[string]CheckInfo{
		"block without evidence":     {Name: "x_check", Response: ResponsePolicy{Block: BlockAlways}},
		"challenge without evidence": {Name: "x_check", Response: ResponsePolicy{ChallengeFirst: true}},
		"family without basis":       {Name: "x_check", Response: ResponsePolicy{Evidence: admission.FamilySSH}},
		"intel on a local family":    {Name: "x_check", Response: ResponsePolicy{Block: BlockAlways, Evidence: admission.FamilySSH, Basis: admission.BasisIntel}},
		"compromise from derived":    {Name: "x_check", Response: ResponsePolicy{Block: BlockAlways, Evidence: admission.FamilyDerived, Basis: admission.BasisCompromise}},
	}
	for name, entry := range cases {
		if err := validateResponsePolicy([]CheckInfo{entry}); err == nil {
			t.Errorf("%s: accepted %+v", name, entry.Response)
		}
	}
	ok := CheckInfo{Name: "x_check", Response: ResponsePolicy{Evidence: admission.FamilyMail, Basis: admission.BasisLocal}}
	if err := validateResponsePolicy([]CheckInfo{ok}); err != nil {
		t.Errorf("evidence without a response policy refused: %v", err)
	}
}

func TestAdmissionPolicyLookup(t *testing.T) {
	cases := []struct {
		in, canonical string
		want          admission.Policy
		ok            bool
	}{
		{"ssh_login_realtime", "ssh_login_unknown_ip", admission.Policy{Family: admission.FamilySSH, Basis: admission.BasisLocal}, true},
		{"ip_reputation", "ip_reputation", admission.Policy{Family: admission.FamilyReputation, Basis: admission.BasisIntel}, true},
		{"mail_account_compromised", "mail_account_compromised", admission.Policy{Family: admission.FamilyMail, Basis: admission.BasisCompromise, MinSeverity: admission.SeverityCritical}, true},
		{"cpanel_login", "cpanel_login", admission.Policy{}, true},
		{"not_a_check", "", admission.Policy{}, false},
		{"", "", admission.Policy{}, false},
	}
	for _, tc := range cases {
		name, p, ok := AdmissionPolicy(tc.in)
		if name != tc.canonical || p != tc.want || ok != tc.ok {
			t.Errorf("AdmissionPolicy(%q) = %q %+v %v, want %q %+v %v", tc.in, name, p, ok, tc.canonical, tc.want, tc.ok)
		}
	}
}

// The Critical-only rule must reach admission, or an advisory finding of such
// a check would become a root there.
func TestAdmissionPolicyCarriesCriticalOnlyFloor(t *testing.T) {
	for _, c := range checkRegistry {
		_, p, ok := AdmissionPolicy(c.Name)
		if !ok {
			t.Fatalf("%q is registered but has no admission policy", c.Name)
		}
		want := admission.Severity(0)
		if c.Response.CriticalOnly {
			want = admission.SeverityCritical
		}
		if p.MinSeverity != want {
			t.Errorf("%q MinSeverity = %s, want %s", c.Name, p.MinSeverity, want)
		}
	}
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := reg.Register(admission.ProducerSpec{ID: "mail_auth", Entry: admission.EntryScan, Observation: admission.ObservationLogCursor, Checks: []string{"mail_account_compromised"}})
	if err != nil {
		t.Fatal(err)
	}
	target, err := admission.CanonicalAddress("192.0.2.1", admission.Caps{})
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	in := admission.EvidenceInput{
		Check:       "mail_account_compromised",
		FindingID:   "0123456789abcdef",
		Severity:    admission.SeverityHigh,
		Observation: admission.ObservationRef{Stream: "maillog", Cursor: "offset=1", Version: 1},
		ObservedAt:  observed,
		Parser:      admission.ParserRef{Name: "dovecot", Version: 1},
		Target:      target,
	}
	if _, mintErr := producer.Mint(in); mintErr == nil {
		t.Error("an advisory mail_account_compromised finding became evidence")
	} else if reason, _ := admission.ReasonOf(mintErr); reason != admission.ReasonPolicy {
		t.Errorf("advisory refusal reason = %s, want policy", reason)
	}
	in.Severity = admission.SeverityCritical
	e, err := producer.Mint(in)
	if err != nil {
		t.Fatal(err)
	}
	if a, err := admission.Assess(target, []admission.Evidence{e}, observed); err != nil || !a.DirectC3 {
		t.Errorf("Critical mail_account_compromised = %+v %v, want direct C3", a, err)
	}
}

// The production lookup must drive the admission registry: every
// classified check can be registered, nothing else can.
func TestAdmissionRegistryAcceptsEveryClassifiedCheck(t *testing.T) {
	reg, err := admission.NewRegistry(AdmissionPolicy)
	if err != nil {
		t.Fatal(err)
	}
	byFamily := map[admission.Family][]string{}
	for name, p := range evidencePolicy {
		byFamily[p.Family] = append(byFamily[p.Family], name)
	}
	for fam, names := range byFamily {
		sort.Strings(names)
		spec := admission.ProducerSpec{ID: admission.ProducerID("fixture_" + fam.String()), Entry: admission.EntryScan, Observation: admission.ObservationLogCursor, Checks: names}
		if _, err := reg.Register(spec); err != nil {
			t.Errorf("family %s: %v", fam, err)
		}
	}
	if _, err := reg.Register(admission.ProducerSpec{ID: "fixture_none", Entry: admission.EntryScan, Observation: admission.ObservationLogCursor, Checks: []string{"cpanel_login"}}); err == nil {
		t.Error("a check without evidence registered")
	}
}

type reviewedEvidenceRestore struct {
	reason, declaration string
}

// reviewedEvidenceRestores lists the functions allowed to write an address
// field of a finding outside a literal. Each copies the field back onto a
// finding that a classified producer built; none writes Check or makes up an
// address. The key is the package directory relative to the repository, a
// dot, and the function name. Pin the whole declaration so changes to the
// source or destination of restored evidence require a new review.
var reviewedEvidenceRestores = map[string]reviewedEvidenceRestore{
	"internal/state.fromPendingRecords": {
		reason: "restores the subnets a finding carried when it was parked at shutdown",
		declaration: `func fromPendingRecords(records []pendingFinding) []alert.Finding {
	if records == nil {
		return nil
	}
	findings := make([]alert.Finding, len(records))
	for i, r := range records {
		findings[i] = r.Finding
		findings[i].CIDRs = r.ResponseCIDRs
		findings[i].SprayTargets = r.ResponseSprayTargets
		findings[i].Claims = r.ResponseClaims
		if r.ResponseObservation != nil {
			findings[i].Observation = *r.ResponseObservation
		}
	}
	return findings
}`,
	},
}

// addressProducer is one alert.Finding literal that carries SourceIP or
// CIDRs.
type addressProducer struct {
	checks []string // resolved check names
	where  string
}

// TestAddressProducersAreClassified walks every production Finding literal
// that sets SourceIP or CIDRs. Each check it can emit must be classified in
// evidencePolicy or listed in notAddressEvidence, so a new address-bearing
// check cannot silently fall outside the response policy.
func TestAddressProducersAreClassified(t *testing.T) {
	producers, unresolved, restored := scanAddressProducersReviewed(t, findRepoRoot(t), reviewedEvidenceRestores)
	for key, restore := range reviewedEvidenceRestores {
		if strings.TrimSpace(restore.reason) == "" {
			t.Errorf("reviewed restore %q has no reason", key)
		}
		if !restored[key] {
			t.Errorf("reviewed restore %q changed or no longer restores an address field", key)
		}
	}
	for _, u := range unresolved {
		t.Errorf("cannot resolve the check name of an address-bearing finding at %s; use a literal or a same-package function that returns literals", u)
	}
	seen := map[string]bool{}
	for _, p := range producers {
		for _, name := range p.checks {
			seen[name] = true
			_, classified := evidencePolicy[name]
			_, excluded := notAddressEvidence[name]
			switch {
			case classified && excluded:
				t.Errorf("%q is both classified and excluded", name)
			case !classified && !excluded:
				t.Errorf("%q carries an address at %s but has no evidence decision: classify it or list it in notAddressEvidence", name, p.where)
			}
		}
	}
	if len(producers) != 68 {
		t.Fatalf("scan found %d address producers; review the change from the pinned 68 producers", len(producers))
	}
	for name, reason := range notAddressEvidence {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%q has no exclusion reason", name)
		}
		if !seen[name] {
			t.Errorf("notAddressEvidence lists %q, which no longer carries an address", name)
		}
	}
	var without []string
	for name := range evidencePolicy {
		if !seen[name] {
			without = append(without, name)
		}
	}
	sort.Strings(without)
	if fmt.Sprint(without) != fmt.Sprint(respondingWithoutAddress) {
		t.Errorf("classified checks without an address producer = %v, want %v", without, respondingWithoutAddress)
	}
}

func scanAddressProducers(t *testing.T, root string) ([]addressProducer, []string) {
	t.Helper()
	producers, unresolved, _ := scanAddressProducersReviewed(t, root, nil)
	return producers, unresolved
}

// scanAddressProducersReviewed also reports which reviewed restores wrote an
// address field.
func scanAddressProducersReviewed(t *testing.T, root string, reviewed map[string]reviewedEvidenceRestore) ([]addressProducer, []string, map[string]bool) {
	t.Helper()
	restored := map[string]bool{}
	contracts := map[string]string{}
	for key, restore := range reviewed {
		if strings.TrimSpace(restore.reason) == "" {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), "", "package reviewed\n"+restore.declaration, 0)
		if err != nil {
			t.Fatalf("reviewed restore %q: %v", key, err)
		}
		if len(f.Decls) != 1 {
			t.Fatalf("reviewed restore %q must contain one plain function", key)
		}
		fn, ok := f.Decls[0].(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil {
			t.Fatalf("reviewed restore %q must contain one plain function", key)
		}
		contracts[key] = canonicalRestoreDeclaration(t, fn)
	}
	var producers []addressProducer
	var unresolved []string
	fset := token.NewFileSet()
	byDir := map[string][]*ast.File{}
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, top), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if info.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			byDir[filepath.Dir(path)] = append(byDir[filepath.Dir(path)], f)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sources := newProducerSources(root, byDir)
	for dir, files := range byDir {
		consts, returns := packageStringValues(files)
		pkg, _ := filepath.Rel(root, dir)
		for _, f := range files {
			for _, decl := range f.Decls {
				restore := ""
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
					// All build variants share this inventory. An ambiguous name
					// cannot inherit the review of one of its declarations.
					if key := filepath.ToSlash(pkg) + "." + fn.Name.Name; contracts[key] != "" && len(sources.files[f].names[fn.Name.Name]) == 1 && canonicalRestoreDeclaration(t, fn) == contracts[key] {
						restore = key
					}
				}
				ast.Inspect(decl, func(n ast.Node) bool {
					var targets []ast.Expr
					switch v := n.(type) {
					case *ast.UnaryExpr:
						if v.Op == token.AND {
							targets = []ast.Expr{v.X}
						}
					case *ast.AssignStmt:
						targets = v.Lhs
					case *ast.RangeStmt:
						targets = []ast.Expr{v.Key, v.Value}
					}
					for _, target := range targets {
						if !sources.evidenceTarget(f, target) {
							continue
						}
						field, direct := ast.Unparen(target).(*ast.SelectorExpr)
						assignment, assigns := n.(*ast.AssignStmt)
						// A closure cannot inherit its enclosing function's review.
						for parent := sources.parents[target]; parent != nil; parent = sources.parents[parent] {
							if _, nested := parent.(*ast.FuncLit); nested {
								direct = false
								break
							}
						}
						if restore != "" && assigns && assignment.Tok == token.ASSIGN && direct && (field.Sel.Name == "SourceIP" || field.Sel.Name == "CIDRs") {
							restored[restore] = true
							continue
						}
						unresolved = append(unresolved, fset.Position(target.Pos()).String()+": evidence field mutation needs a reviewed producer contract")
					}
					return true
				})
				for _, lit := range sources.addressLiterals(f, decl) {
					if sources.shape(sources.literalType(f, lit)).expr == nil {
						unresolved = append(unresolved, fset.Position(lit.Pos()).String()+": unresolved address-bearing type needs a reviewed producer contract")
						continue
					}
					positional := false
					for _, elt := range lit.Elts {
						if _, keyed := elt.(*ast.KeyValueExpr); !keyed {
							positional = true
						}
					}
					if positional {
						unresolved = append(unresolved, fset.Position(lit.Pos()).String()+": positional finding needs named fields")
						continue
					}
					check, carries := findingCheckField(lit)
					if !carries {
						continue
					}
					where := fset.Position(lit.Pos()).String()
					rel, _ := filepath.Rel(root, where)
					names, ok := resolveCheckNames(check, decl, consts, returns)
					if !ok {
						unresolved = append(unresolved, rel)
						continue
					}
					producers = append(producers, addressProducer{checks: names, where: rel})
				}
			}
		}
	}
	return producers, unresolved, restored
}

// A fresh file set discards layout, keeping formatting and comments out
// of the contract while preserving the entire function's syntax.
func canonicalRestoreDeclaration(t *testing.T, fn *ast.FuncDecl) string {
	t.Helper()
	var out bytes.Buffer
	if err := format.Node(&out, token.NewFileSet(), fn); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func findingCheckField(lit *ast.CompositeLit) (ast.Expr, bool) {
	var check ast.Expr
	carries := false
	for _, e := range lit.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "Check":
			check = kv.Value
		case "SourceIP", "CIDRs":
			carries = true
		}
	}
	return check, carries
}

// packageStringValues collects package-level string constants and the
// functions whose every return is a string literal.
func packageStringValues(files []*ast.File) (map[string]string, map[string][]string) {
	consts := map[string]string{}
	returns := map[string][]string{}
	declarations := map[string]int{}
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch v := spec.(type) {
					case *ast.ValueSpec:
						for _, name := range v.Names {
							declarations[name.Name]++
						}
					case *ast.TypeSpec:
						declarations[v.Name.Name]++
					}
				}
				if d.Tok != token.CONST {
					continue
				}
				for _, spec := range d.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						if i < len(vs.Values) {
							if s, ok := stringLit(vs.Values[i]); ok {
								consts[name.Name] = s
							}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv != nil {
					continue
				}
				declarations[d.Name.Name]++
				if d.Body == nil {
					continue
				}
				var vals []string
				all := true
				ast.Inspect(d.Body, func(n ast.Node) bool {
					if _, nested := n.(*ast.FuncLit); nested {
						return false
					}
					ret, ok := n.(*ast.ReturnStmt)
					if !ok {
						return true
					}
					if len(ret.Results) != 1 {
						all = false
						return false
					}
					s, ok := stringLit(ret.Results[0])
					if !ok {
						all = false
						return false
					}
					vals = append(vals, s)
					return true
				})
				if all && len(vals) > 0 {
					returns[d.Name.Name] = vals
				}
			}
		}
	}
	// All build variants are scanned. Conflicting definitions cannot inherit
	// whichever literal happened to be visited last.
	for name, count := range declarations {
		if count > 1 {
			delete(consts, name)
			delete(returns, name)
		}
	}
	return consts, returns
}

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	return s, err == nil
}

// resolveCheckNames resolves a Check expression to the names it can hold:
// a literal, a package constant, or a local variable every assignment of
// which is a literal, a constant, or a call to a literal-returning
// function of the same package.
func resolveCheckNames(check ast.Expr, decl ast.Decl, consts map[string]string, returns map[string][]string) ([]string, bool) {
	value := func(e ast.Expr) ([]string, bool) {
		if s, ok := stringLit(e); ok {
			return []string{s}, true
		}
		if id, ok := e.(*ast.Ident); ok {
			if id.Obj != nil {
				if id.Obj.Kind != ast.Con {
					return nil, false
				}
				if vs, ok := id.Obj.Decl.(*ast.ValueSpec); ok {
					for i, name := range vs.Names {
						if name.Obj == id.Obj && i < len(vs.Values) {
							if s, ok := stringLit(vs.Values[i]); ok {
								return []string{s}, true
							}
						}
					}
				}
				return nil, false
			}
			if s, ok := consts[id.Name]; ok {
				return []string{s}, true
			}
		}
		if call, ok := e.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && (id.Obj == nil || id.Obj.Kind == ast.Fun) {
				if vals, ok := returns[id.Name]; ok {
					return vals, true
				}
			}
		}
		return nil, false
	}
	if names, ok := value(check); ok {
		return names, true
	}
	id, ok := check.(*ast.Ident)
	if !ok || id.Obj == nil || id.Obj.Kind != ast.Var {
		return nil, false
	}
	switch id.Obj.Decl.(type) {
	case *ast.AssignStmt, *ast.ValueSpec:
	default:
		return nil, false
	}
	// A package variable can be changed by another function between the local
	// assignment and emission. Only variables declared inside this producer
	// have all their writes covered by the scan below.
	local := false
	ast.Inspect(decl, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch fn := n.(type) {
		case *ast.FuncDecl:
			body = fn.Body
		case *ast.FuncLit:
			body = fn.Body
		default:
			return true
		}
		if body != nil {
			ast.Inspect(body, func(n ast.Node) bool {
				local = local || n == id.Obj.Decl
				return !local
			})
		}
		return false
	})
	if !local {
		return nil, false
	}
	var names []string
	resolved := true
	assigned := false
	ast.Inspect(decl, func(n ast.Node) bool {
		if loop, ok := n.(*ast.RangeStmt); ok {
			for _, e := range []ast.Expr{loop.Key, loop.Value} {
				if assigned, ok := ast.Unparen(e).(*ast.Ident); ok && assigned.Obj == id.Obj {
					resolved = false
				}
			}
		}
		if ref, ok := n.(*ast.UnaryExpr); ok && ref.Op == token.AND {
			if escaped, ok := ast.Unparen(ref.X).(*ast.Ident); ok && escaped.Obj == id.Obj {
				resolved = false
			}
		}
		if vs, ok := n.(*ast.ValueSpec); ok {
			for i, name := range vs.Names {
				if name.Obj != id.Obj {
					continue
				}
				assigned = true
				if len(vs.Names) != len(vs.Values) {
					resolved = false
					continue
				}
				vals, ok := value(vs.Values[i])
				if !ok {
					resolved = false
					continue
				}
				names = append(names, vals...)
			}
		}
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			if l, ok := ast.Unparen(lhs).(*ast.Ident); !ok || l.Obj != id.Obj {
				continue
			}
			assigned = true
			if (as.Tok != token.ASSIGN && as.Tok != token.DEFINE) || len(as.Rhs) != len(as.Lhs) {
				resolved = false
				continue
			}
			vals, ok := value(as.Rhs[i])
			if !ok {
				resolved = false
				continue
			}
			names = append(names, vals...)
		}
		return true
	})
	return names, resolved && assigned
}

func TestAddressProducerScannerForms(t *testing.T) {
	for _, tc := range []struct {
		name, source          string
		producers, unresolved int
	}{
		{"named literal", `package fixture; import "github.com/pidginhost/csm/internal/alert"; var f = alert.Finding{Check:"ssh_login_unknown_ip", SourceIP:"192.0.2.1"}`, 1, 0},
		{"import alias", `package fixture; import events "github.com/pidginhost/csm/internal/alert"; var f = events.Finding{Check:"ssh_login_unknown_ip", SourceIP:"192.0.2.1"}`, 1, 0},
		{"type alias", `package fixture; import "github.com/pidginhost/csm/internal/alert"; type F = alert.Finding; var f = F{Check:"ssh_login_unknown_ip", SourceIP:"192.0.2.1"}`, 1, 0},
		{"elided literals", `package fixture; import "github.com/pidginhost/csm/internal/alert"; var f = []alert.Finding{{Check:"ssh_login_unknown_ip", SourceIP:"192.0.2.1"}}; var m = map[string]alert.Finding{"a":{Check:"http_asn_crawl", CIDRs:[]string{"192.0.2.0/24"}}}`, 2, 0},
		{"elided dot import", `package fixture; import . "github.com/pidginhost/csm/internal/alert"; var f = []Finding{{Check:"ssh_login_unknown_ip", SourceIP:"192.0.2.1"}}`, 1, 0},
		{"elided dot import missing check", `package fixture; import . "github.com/pidginhost/csm/internal/alert"; var f = []Finding{{SourceIP:"192.0.2.1"}}`, 0, 1},
		{"missing check", `package fixture; import events "github.com/pidginhost/csm/internal/alert"; var f = events.Finding{SourceIP:"192.0.2.1"}`, 0, 1},
		{"field assignment", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f() { var a alert.Finding; a.SourceIP = "192.0.2.1" }`, 0, 1},
		{"parenthesized field assignment", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f() { var a alert.Finding; (a.SourceIP) = "192.0.2.1" }`, 0, 1},
		{"escaped address field", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f() { var a alert.Finding; fill(&(a.SourceIP)) }`, 0, 1},
		{"escaped cidrs field", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f() { var a alert.Finding; fill(&a.CIDRs) }`, 0, 1},
		{"positional finding", `package alert; var f = Finding{0, "ssh_login_unknown_ip", "192.0.2.1"}`, 0, 1},
		{"range assigned check", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f() { check := "ssh_login_unknown_ip"; for _, check = range []string{"not_a_check"} { _ = alert.Finding{Check:check, SourceIP:"192.0.2.1"} } }`, 0, 1},
		{"parenthesized check assignment", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f() { check := "ssh_login_unknown_ip"; (check) = dynamic(); _ = alert.Finding{Check:check, SourceIP:"192.0.2.1"} }`, 0, 1},
		{"finding check replacement", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f() { a := alert.Finding{Check:"ssh_login_unknown_ip", SourceIP:"192.0.2.1"}; a.Check = "not_a_check" }`, 1, 1},
		{"finding parameter replacement", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f(a *alert.Finding) { a.Check = "not_a_check" }`, 0, 1},
		{"finding copy replacement", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f() { a := alert.Finding{Check:"ssh_login_unknown_ip", SourceIP:"192.0.2.1"}; b := &a; b.Check = "not_a_check" }`, 1, 1},
		{"finding escaped check", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f(a *alert.Finding) { fill(&a.Check) }`, 0, 1},
		{"constructor result replacement", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func makeFinding() alert.Finding { return alert.Finding{Check:"ssh_login_unknown_ip", SourceIP:"192.0.2.1"} }; func f() { a := makeFinding(); a.Check = "not_a_check" }`, 1, 1},
		{"method result replacement", `package fixture; import "github.com/pidginhost/csm/internal/alert"; type maker struct{}; func (maker) makeFinding() alert.Finding { return alert.Finding{Check:"ssh_login_unknown_ip", SourceIP:"192.0.2.1"} }; func f(m maker) { a := m.makeFinding(); a.Check = "not_a_check" }`, 1, 1},
		{"embedded finding replacement", `package fixture; import "github.com/pidginhost/csm/internal/alert"; type wrapper struct { alert.Finding }; func f(a *wrapper) { a.Check = "not_a_check" }`, 0, 1},
		{"nested finding replacement", `package fixture; import "github.com/pidginhost/csm/internal/alert"; type wrapper struct { Finding alert.Finding }; func f(a *wrapper) { a.Finding.Check = "not_a_check" }`, 0, 1},
		{"slice element replacement", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f(a []alert.Finding) { a[0].Check = "not_a_check" }`, 0, 1},
		{"generic result replacement", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func identity[T any](v T) T { return v }; func f() { a := identity(alert.Finding{Check:"ssh_login_unknown_ip", SourceIP:"192.0.2.1"}); a.Check = "not_a_check" }`, 1, 1},
		{"generic explicit replacement", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func identity[T any](v T) T { return v }; func f(a alert.Finding) { b := identity[alert.Finding](a); b.Check = "not_a_check" }`, 0, 1},
		{"generic elided missing check", `package fixture; import "github.com/pidginhost/csm/internal/alert"; type findings[T any] []alert.Finding; var a = findings[int]{{SourceIP:"192.0.2.1"}}`, 0, 1},
		{"named slice missing check", `package fixture; import "github.com/pidginhost/csm/internal/alert"; type findings []alert.Finding; var a = findings{{SourceIP:"192.0.2.1"}}`, 0, 1},
		{"nested elided missing check", `package fixture; import "github.com/pidginhost/csm/internal/alert"; var a = [][]alert.Finding{{{SourceIP:"192.0.2.1"}}}`, 0, 1},
		{"other record literal", `package fixture; type record struct { Check, SourceIP string }; var a = record{Check:"other", SourceIP:"192.0.2.1"}`, 0, 0},
		{"other record address assignment", `package fixture; type record struct { SourceIP string }; func f(a *record) { a.SourceIP = "192.0.2.1" }`, 0, 0},
		{"other record address escape", `package fixture; type record struct { SourceIP string }; func fill(*string) {}; func f(a *record) { fill(&a.SourceIP) }`, 0, 0},
		{"embedded finding shadow", `package fixture; import "github.com/pidginhost/csm/internal/alert"; type wrapper struct { alert.Finding; Check string }; func f(a *wrapper) { a.Check = "other" }`, 0, 0},
		{"range finding replacement", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f(a []alert.Finding) { for _, item := range a { item.Check = "not_a_check" } }`, 0, 1},
		{"tuple constructor replacement", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func makeFinding() (bool, alert.Finding) { return true, alert.Finding{Check:"ssh_login_unknown_ip", SourceIP:"192.0.2.1"} }; func f() { _, a := makeFinding(); a.Check = "not_a_check" }`, 1, 1},
		{"unknown producer type", `package fixture; var a = unknown{Check:"ssh_login_unknown_ip", SourceIP:"192.0.2.1"}`, 0, 1},
		{"other method result", `package fixture; type record struct { Check string }; type maker struct{}; func (maker) create() record { return record{} }; func f(m maker) { a := m.create(); a.Check = "other" }`, 0, 0},
		{"other constructor result", `package fixture; type record struct { Check string }; func create() record { return record{} }; func f() { a := create(); a.Check = "other" }`, 0, 0},
		{"embedded field at shallow depth", `package fixture; import "github.com/pidginhost/csm/internal/alert"; type deep struct { alert.Finding }; type record struct { Check string }; type wrapper struct { deep; record }; func f(a *wrapper) { a.Check = "other" }`, 0, 0},
		{"unknown embedding", `package fixture; type record struct { Check string }; type wrapper struct { unknown; record }; func f(a *wrapper) { a.Check = "not_a_check" }`, 0, 1},
		{"embedded unrelated field", `package fixture; type record struct { Check string }; type empty struct{}; type wrapper struct { empty; record }; func f(a *wrapper) { a.Check = "other" }`, 0, 0},
		{"recursive unrelated field", `package fixture; type record struct { *record; Check string }; func f(a *record) { a.Check = "other" }`, 0, 0},
		{"nested map finding", `package fixture; import "github.com/pidginhost/csm/internal/alert"; var a = map[string][]*alert.Finding{"a":{{SourceIP:"192.0.2.1"}}}`, 0, 1},
		{"range finding field assignment", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f(a *alert.Finding, names []string) { for _, a.Check = range names {} }`, 0, 1},
		{"cidr element assignment", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f(a *alert.Finding) { a.CIDRs[0] = "192.0.2.0/24" }`, 0, 1},
		{"cidr element escape", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func fill(*string) {}; func f(a *alert.Finding) { fill(&a.CIDRs[0]) }`, 0, 1},
		{"other cidr element", `package fixture; type record struct { CIDRs []string }; func f(a *record) { a.CIDRs[0] = "192.0.2.0/24" }`, 0, 0},
		{"package variable check", `package fixture; import "github.com/pidginhost/csm/internal/alert"; var check string; func rename() { check = "not_a_check" }; func f() { check = "ssh_login_unknown_ip"; rename(); _ = alert.Finding{Check:check, SourceIP:"192.0.2.1"} }`, 0, 1},
		{"other record check", `package fixture; type record struct { Check string }; func f(a *record) { a.Check = "other" }`, 0, 0},
		{"constant shadow", `package fixture; import "github.com/pidginhost/csm/internal/alert"; const check = "ssh_login_unknown_ip"; func f(check string) { _ = alert.Finding{Check:check, SourceIP:"192.0.2.1"} }`, 0, 1},
		{"parameter shadow", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f(check string) { if true { check := "ssh_login_unknown_ip"; _ = check }; _ = alert.Finding{Check:check, SourceIP:"192.0.2.1"} }`, 0, 1},
		{"variable declaration", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f() { var check = "ssh_login_unknown_ip"; _ = alert.Finding{Check:check, SourceIP:"192.0.2.1"} }`, 1, 0},
		{"compound assignment", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func f() { check := "ssh_login_unknown_ip"; check += "_suffix"; _ = alert.Finding{Check:check, SourceIP:"192.0.2.1"} }`, 0, 1},
		{"parenthesized escape", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func update(p *string) { *p = "not_a_check" }; func f() { check := "ssh_login_unknown_ip"; update(&(check)); _ = alert.Finding{Check:check, SourceIP:"192.0.2.1"} }`, 0, 1},
		{"escaped variable", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func update(p *string) { *p = "not_a_check" }; func f() { check := "ssh_login_unknown_ip"; update(&check); _ = alert.Finding{Check:check, SourceIP:"192.0.2.1"} }`, 0, 1},
		{"dynamic helper", `package fixture; import "github.com/pidginhost/csm/internal/alert"; func check() string { return dynamic() }; var f = alert.Finding{Check:check(), SourceIP:"192.0.2.1"}`, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"internal", "cmd"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(root, "internal", "fixture.go"), []byte(tc.source), 0600); err != nil {
				t.Fatal(err)
			}
			producers, unresolved := scanAddressProducers(t, root)
			if len(producers) != tc.producers || len(unresolved) != tc.unresolved {
				t.Fatalf("got %d producers, %d unresolved; want %d, %d", len(producers), len(unresolved), tc.producers, tc.unresolved)
			}
		})
	}
}

func TestAddressProducerScannerUsesLocalConstant(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"internal", "cmd"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	source := `package fixture; import "github.com/pidginhost/csm/internal/alert"; const check = "ssh_login_unknown_ip"; func f() { const check = "not_a_check"; _ = alert.Finding{Check:check, SourceIP:"192.0.2.1"} }`
	if err := os.WriteFile(filepath.Join(root, "internal", "fixture.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	producers, unresolved := scanAddressProducers(t, root)
	if len(unresolved) != 0 || len(producers) != 1 || len(producers[0].checks) != 1 || producers[0].checks[0] != "not_a_check" {
		t.Fatalf("scanner used the shadowed package constant: %v %v", producers, unresolved)
	}
}

func TestAddressProducerScannerResolvesPackageTypes(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"internal/model/type.go": `package model
import events "github.com/pidginhost/csm/internal/alert"
type Finding = events.Finding
type Findings []Finding
type Record struct { Check, SourceIP string }
func NewRecord() Record { return Record{} }
`,
		"internal/producer/types.go": `package producer
import "github.com/pidginhost/csm/internal/model"
type Findings = model.Findings
type Wrapper struct { model.Finding }
`,
		"internal/producer/use.go": `package producer
import "github.com/pidginhost/csm/internal/model"
var classified = Findings{{Check:"ssh_login_unknown_ip", SourceIP:"192.0.2.1"}}
var missing = Findings{{SourceIP:"192.0.2.1"}}
func rewrite(w *Wrapper) { w.Check = "not_a_check" }
func unrelated() { r := model.NewRecord(); r.Check = "other"; r.SourceIP = "192.0.2.1" }
`,
	}
	if err := os.MkdirAll(filepath.Join(root, "cmd"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, source := range files {
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	producers, unresolved := scanAddressProducers(t, root)
	if len(producers) != 1 || len(producers[0].checks) != 1 || producers[0].checks[0] != "ssh_login_unknown_ip" {
		t.Fatalf("cross-package producer = %v, want exactly ssh_login_unknown_ip", producers)
	}
	if len(unresolved) != 2 {
		t.Fatalf("unresolved = %v, want the missing check and promoted field write", unresolved)
	}
	for _, line := range []string{"use.go:4:", "use.go:5:"} {
		count := 0
		for _, where := range unresolved {
			if strings.Contains(where, line) {
				count++
			}
		}
		if count != 1 {
			t.Errorf("%s reported %d times in %v, want once", line, count, unresolved)
		}
	}
}

func TestAddressProducerScannerRefusesAmbiguousBuildValues(t *testing.T) {
	for name, declarations := range map[string][2]string{
		"constant": {`const check = "ssh_login_unknown_ip"`, `const check = "not_a_check"`},
		"helper":   {`func check() string { return "ssh_login_unknown_ip" }`, `func check() string { return dynamic() }`},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"internal", "cmd"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			for i, declaration := range declarations {
				// Each definition belongs to a different build, but the source
				// inventory must not pick one arbitrarily for a shared producer.
				source := fmt.Sprintf("//go:build variant%d\n\npackage fixture\n%s\n", i, declaration)
				if err := os.WriteFile(filepath.Join(root, "internal", fmt.Sprintf("variant%d.go", i)), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			value := "check"
			if name == "helper" {
				value += "()"
			}
			source := `package fixture; import "github.com/pidginhost/csm/internal/alert"; var f = alert.Finding{Check:` + value + `, SourceIP:"192.0.2.1"}`
			if err := os.WriteFile(filepath.Join(root, "internal", "producer.go"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			producers, unresolved := scanAddressProducers(t, root)
			if len(producers) != 0 || len(unresolved) != 1 || !strings.Contains(unresolved[0], "producer.go:") {
				t.Fatalf("ambiguous builds yielded %v / %v, want one unresolved producer", producers, unresolved)
			}
		})
	}
}

// Only a listed function may write an address field outside a literal, only
// address fields, and the listing must name a function that exists.
func TestAddressProducerScannerHonoursReviewedRestores(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "cmd"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "internal", "store"), 0700); err != nil {
		t.Fatal(err)
	}
	source := `package store
import "github.com/pidginhost/csm/internal/alert"
func restore(f *alert.Finding, cidrs []string, ip string) { f.CIDRs = cidrs; f.SourceIP = ip }
func rename(f *alert.Finding) { f.Check = "other" }
func rewrite(f *alert.Finding) { f.CIDRs = nil }
type cache struct{}
func (cache) restore(f *alert.Finding) { f.SourceIP = "" }
`
	if err := os.WriteFile(filepath.Join(root, "internal", "store", "store.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	reviewed := map[string]reviewedEvidenceRestore{
		"internal/store.restore": {"fixture restore", `func restore(f *alert.Finding, cidrs []string, ip string) { f.CIDRs = cidrs; f.SourceIP = ip }`},
		"internal/store.rename":  {"fixture rename", `func rename(f *alert.Finding) { f.Check = "other" }`},
		"internal/store.missing": {"fixture stale entry", `func missing(f *alert.Finding) { f.CIDRs = nil }`},
	}
	_, unresolved, used := scanAddressProducersReviewed(t, root, reviewed)
	if len(unresolved) != 3 {
		t.Fatalf("unresolved = %v, want the Check write, the unlisted function and the method", unresolved)
	}
	for _, line := range []string{"store.go:4:", "store.go:5:", "store.go:7:"} {
		found := false
		for _, where := range unresolved {
			found = found || strings.Contains(where, line)
		}
		if !found {
			t.Errorf("%s not reported in %v", line, unresolved)
		}
	}
	if !used["internal/store.restore"] || used["internal/store.rename"] || used["internal/store.missing"] {
		t.Fatalf("used = %v, want only the restore that writes address fields", used)
	}
}

func TestAddressProducerScannerBoundsReviewedRestores(t *testing.T) {
	for _, tc := range []struct {
		name, body string
	}{
		{"closure", `func() { f.SourceIP = "192.0.2.2" }()`},
		{"nested closure", `func() { func() { f.CIDRs = nil }() }()`},
		{"address pointer", `_ = &f.SourceIP`},
		{"subnet pointer", `_ = &f.CIDRs`},
		{"subnet element", `f.CIDRs[0] = "192.0.2.0/24"`},
		{"subnet element pointer", `_ = &f.CIDRs[0]`},
		{"range assignment", `for _, f.SourceIP = range []string{"192.0.2.2"} {}`},
		{"compound assignment", `f.SourceIP += "2"`},
		{"check assignment", `f.Check = "other"`},
		{"check pointer", `_ = &f.Check`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"cmd", "internal/store"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			declaration := `func restore(f *alert.Finding) { ` + tc.body + ` }`
			source := `package store; import "github.com/pidginhost/csm/internal/alert"; ` + declaration
			if err := os.WriteFile(filepath.Join(root, "internal/store/store.go"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			reviewed := map[string]reviewedEvidenceRestore{"internal/store.restore": {"fixture restore", declaration}}
			producers, unresolved, used := scanAddressProducersReviewed(t, root, reviewed)
			if len(producers) != 0 || len(unresolved) != 1 || !strings.Contains(unresolved[0], "store.go:") || used["internal/store.restore"] {
				t.Fatalf("unsafe restore yielded %v / %v / %v, want one unresolved mutation and no used restore", producers, unresolved, used)
			}
		})
	}
}

func TestAddressProducerScannerRejectsUnreviewedRestoreChanges(t *testing.T) {
	const declaration = `func fromPendingRecords(records []pendingFinding) []alert.Finding {
	if records == nil {
		return nil
	}
	findings := make([]alert.Finding, len(records))
	for i, r := range records {
		findings[i] = r.Finding
		findings[i].CIDRs = r.ResponseCIDRs
		findings[i].SprayTargets = r.ResponseSprayTargets
		findings[i].Claims = r.ResponseClaims
		if r.ResponseObservation != nil {
			findings[i].Observation = *r.ResponseObservation
		}
	}
	return findings
}`
	for _, tc := range []struct {
		name, declaration string
		unresolved        int
		used              bool
	}{
		{"reviewed copy", declaration, 0, true},
		{"layout and comments", strings.ReplaceAll(strings.ReplaceAll(declaration, "\n", "\n\n"), "return findings", "/* restored */ return findings"), 0, true},
		{"stale restore", strings.Replace(declaration, "findings[i].CIDRs = r.ResponseCIDRs", "", 1), 0, false},
		{"new source", strings.Replace(declaration, "r.ResponseCIDRs", `[]string{"192.0.2.0/24"}`, 1), 1, false},
		{"new field", strings.Replace(declaration, "return findings", `findings[0].SourceIP = "192.0.2.2"; return findings`, 1), 2, false},
		{"changed provenance", strings.Replace(declaration, "findings[i] = r.Finding", `findings[i] = alert.Finding{Check: "other"}`, 1), 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"cmd", "internal/state"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			source := `package state; import "github.com/pidginhost/csm/internal/alert"; type pendingFinding struct { alert.Finding; ResponseCIDRs, ResponseSprayTargets []string }; ` + tc.declaration
			if err := os.WriteFile(filepath.Join(root, "internal/state/pending.go"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			producers, unresolved, used := scanAddressProducersReviewed(t, root, reviewedEvidenceRestores)
			if len(producers) != 0 || len(unresolved) != tc.unresolved || used["internal/state.fromPendingRecords"] != tc.used {
				t.Fatalf("restore yielded %v / %v / %v, want %d unresolved and used = %v", producers, unresolved, used, tc.unresolved, tc.used)
			}
		})
	}
}

func TestAddressProducerScannerScopesReviewedRestores(t *testing.T) {
	const declaration = `func restore(f *alert.Finding, cidrs []string) { f.CIDRs = cidrs }`
	const source = `package store; import "github.com/pidginhost/csm/internal/alert"; ` + declaration
	for _, tc := range []struct {
		name, otherPath, otherSource string
		unresolved                   int
		used                         bool
	}{
		{"other package", "internal/other/store.go", source, 1, true},
		{"build variant", "internal/store/store_other.go", "//go:build other\n\n" + source, 2, false},
		{"generated variant", "internal/store/store_generated.go", "//go:build other\n\n// Code generated by fixture. DO NOT EDIT.\n" + source, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "cmd"), 0700); err != nil {
				t.Fatal(err)
			}
			for path, content := range map[string]string{"internal/store/store.go": "//go:build !other\n\n" + source, tc.otherPath: tc.otherSource} {
				path = filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			reviewed := map[string]reviewedEvidenceRestore{"internal/store.restore": {"fixture restore", declaration}}
			producers, unresolved, used := scanAddressProducersReviewed(t, root, reviewed)
			if len(producers) != 0 || len(unresolved) != tc.unresolved || used["internal/store.restore"] != tc.used {
				t.Fatalf("scoped restores yielded %v / %v / %v, want %d unresolved and used = %v", producers, unresolved, used, tc.unresolved, tc.used)
			}
			paths := []string{tc.otherPath}
			if !tc.used {
				paths = append(paths, "internal/store/store.go")
			}
			for _, path := range paths {
				count := 0
				for _, where := range unresolved {
					if strings.Contains(where, filepath.FromSlash(path)+":") {
						count++
					}
				}
				if count != 1 {
					t.Errorf("%s reported %d times in %v, want once", path, count, unresolved)
				}
			}
		})
	}
}
