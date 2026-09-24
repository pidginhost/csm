package checks

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

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
	"api_auth_failure",
	"cpanel_multi_ip_login",
	"email_compromised_account",
	"webmail_bruteforce",
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
	producers, unresolved := scanAddressProducers(t, findRepoRoot(t))
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
	if len(producers) != 65 {
		t.Fatalf("scan found %d address producers; review the change from the pinned 65 producers", len(producers))
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
	var producers []addressProducer
	var unresolved []string
	fset := token.NewFileSet()
	for _, top := range []string{"internal", "cmd"} {
		byDir := map[string][]*ast.File{}
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
		for _, files := range byDir {
			consts, returns := packageStringValues(files)
			for _, f := range files {
				for _, decl := range f.Decls {
					ast.Inspect(decl, func(n ast.Node) bool {
						if ref, ok := n.(*ast.UnaryExpr); ok && ref.Op == token.AND {
							if field, ok := ast.Unparen(ref.X).(*ast.SelectorExpr); ok && (field.Sel.Name == "SourceIP" || field.Sel.Name == "CIDRs" || (field.Sel.Name == "Check" && isFindingValue(f, field.X, map[ast.Expr]bool{}))) {
								unresolved = append(unresolved, fset.Position(ref.Pos()).String()+": escaped evidence field needs a reviewed producer contract")
							}
						}
						as, ok := n.(*ast.AssignStmt)
						if !ok {
							return true
						}
						for _, lhs := range as.Lhs {
							if field, ok := ast.Unparen(lhs).(*ast.SelectorExpr); ok && (field.Sel.Name == "SourceIP" || field.Sel.Name == "CIDRs" || (field.Sel.Name == "Check" && isFindingValue(f, field.X, map[ast.Expr]bool{}))) {
								unresolved = append(unresolved, fset.Position(lhs.Pos()).String()+": evidence field assignment needs a reviewed producer contract")
							}
						}
						return true
					})
					for _, lit := range addressFindingLiterals(f, decl) {
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
	}
	return producers, unresolved
}

func isFindingTypeExpr(f *ast.File, e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.SelectorExpr:
		x, ok := t.X.(*ast.Ident)
		if !ok || t.Sel.Name != "Finding" {
			return false
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || path != "github.com/pidginhost/csm/internal/alert" {
				continue
			}
			name := "alert"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			if x.Name == name {
				return true
			}
		}
		return false
	case *ast.Ident:
		if t.Obj != nil {
			if spec, ok := t.Obj.Decl.(*ast.TypeSpec); ok {
				return isFindingTypeExpr(f, spec.Type)
			}
		}
		if t.Name != "Finding" {
			return false
		}
		if f.Name.Name == "alert" {
			return true
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err == nil && path == "github.com/pidginhost/csm/internal/alert" && imp.Name != nil && imp.Name.Name == "." {
				return true
			}
		}
		return false
	case *ast.StarExpr:
		return isFindingTypeExpr(f, t.X)
	}
	return false
}

// isFindingValue follows declared Finding values and local copies so a
// later check-name write cannot bypass the literal's policy classification.
func isFindingValue(f *ast.File, e ast.Expr, seen map[ast.Expr]bool) bool {
	e = ast.Unparen(e)
	if e == nil || seen[e] {
		return false
	}
	seen[e] = true
	switch v := e.(type) {
	case *ast.CompositeLit:
		return isFindingTypeExpr(f, v.Type)
	case *ast.UnaryExpr:
		return isFindingValue(f, v.X, seen)
	case *ast.StarExpr:
		return isFindingValue(f, v.X, seen)
	case *ast.Ident:
		if v.Obj == nil {
			return false
		}
		switch d := v.Obj.Decl.(type) {
		case *ast.Field:
			return isFindingTypeExpr(f, d.Type)
		case *ast.ValueSpec:
			if isFindingTypeExpr(f, d.Type) {
				return true
			}
			for i, name := range d.Names {
				if name.Obj == v.Obj && i < len(d.Values) {
					return isFindingValue(f, d.Values[i], seen)
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range d.Lhs {
				if name, ok := ast.Unparen(lhs).(*ast.Ident); ok && name.Obj == v.Obj && i < len(d.Rhs) {
					return isFindingValue(f, d.Rhs[i], seen)
				}
			}
		}
	}
	return false
}

// addressFindingLiterals returns Finding literals in decl, including elided
// literals inside []alert.Finding and map values of that type.
func addressFindingLiterals(f *ast.File, decl ast.Decl) []*ast.CompositeLit {
	var out []*ast.CompositeLit
	seen := map[*ast.CompositeLit]bool{}
	add := func(cl *ast.CompositeLit) {
		if !seen[cl] {
			seen[cl] = true
			out = append(out, cl)
		}
	}
	ast.Inspect(decl, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		check, carries := findingCheckField(cl)
		if (cl.Type != nil && isFindingTypeExpr(f, cl.Type)) || (check != nil && carries) {
			add(cl)
		}
		var elt ast.Expr
		switch t := cl.Type.(type) {
		case *ast.ArrayType:
			elt = t.Elt
		case *ast.MapType:
			elt = t.Value
		}
		if elt == nil || !isFindingTypeExpr(f, elt) {
			return true
		}
		for _, e := range cl.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				e = kv.Value
			}
			if u, ok := e.(*ast.UnaryExpr); ok {
				e = u.X
			}
			if inner, ok := e.(*ast.CompositeLit); ok && inner.Type == nil {
				add(inner)
			}
		}
		return true
	})
	return out
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
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
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
				if d.Recv != nil || d.Body == nil {
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
